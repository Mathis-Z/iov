import http from 'http';
import https from 'https';
import { schema } from '@osd/config-schema';
import { IBasePath, IRouter, Logger } from '../../../../src/core/server';

// The browser loads ETSO's dashboard from here, on the Wazuh dashboard's own
// origin, and this server fetches it from ETSO over plain HTTP. So the iframe
// needs no certificate or port of its own, and, like every route here, it
// requires a Wazuh login (authRequired defaults to true).
export const ETSO_DASHBOARD_ROUTE = '/api/etso/dashboard';

// A first build after an ETSO restart reads the whole indexer.
const TIMEOUT_MS = 300_000;

// Everything else ETSO sends (cookies, server headers) stays behind.
const PASSED_HEADERS = ['content-type', 'cache-control', 'etag', 'last-modified'];

interface EtsoResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

class EtsoTimeout extends Error {}

function fetchFromEtso(url: URL): Promise<EtsoResponse> {
  const client = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = client.get(
      url,
      // Uncompressed: the Wazuh dashboard compresses the response itself.
      { headers: { accept: '*/*', 'accept-encoding': 'identity' }, timeout: TIMEOUT_MS },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () =>
          resolve({
            statusCode: response.statusCode ?? 502,
            headers: response.headers,
            body: Buffer.concat(chunks),
          })
        );
        response.on('error', reject);
      }
    );
    request.on('timeout', () => request.destroy(new EtsoTimeout()));
    request.on('error', reject);
  });
}

/**
 * The ETSO URL for a path under the route, or null if it would leave ETSO's
 * /dashboard/. The router hands over the path decoded, so "..%2F" arrives as
 * "../": dot segments are refused outright, and each segment is re-encoded so
 * a decoded "?" or "#" stays part of the path.
 */
export function etsoTarget(etsoUrl: string, path: string, search: string): URL | null {
  const segments = path.split('/');
  if (segments.some((segment) => segment === '.' || segment === '..')) {
    return null;
  }
  const target = new URL(`/dashboard/${segments.map(encodeURIComponent).join('/')}`, etsoUrl);
  if (!target.pathname.startsWith('/dashboard/')) {
    return null;
  }
  target.search = search;
  return target;
}

export function registerEtsoProxyRoutes(
  router: IRouter,
  basePath: IBasePath,
  etsoUrl: () => string,
  logger: Logger
) {
  // The page's URLs are relative, so it must be loaded with the trailing slash.
  router.get(
    { path: ETSO_DASHBOARD_ROUTE, validate: false },
    async (context, request, response) =>
      response.redirected({
        headers: { location: `${basePath.get(request)}${ETSO_DASHBOARD_ROUTE}/${request.url.search}` },
      })
  );

  router.get(
    {
      path: `${ETSO_DASHBOARD_ROUTE}/{path*}`,
      validate: {
        params: schema.object({ path: schema.maybe(schema.string()) }),
        query: schema.object({}, { unknowns: 'allow' }),
      },
      options: { timeout: { idleSocket: TIMEOUT_MS } },
    },
    async (context, request, response) => {
      const target = etsoTarget(etsoUrl(), request.params.path ?? '', request.url.search);
      if (target === null) {
        return response.notFound();
      }

      let etso: EtsoResponse;
      try {
        etso = await fetchFromEtso(target);
      } catch (error) {
        if (error instanceof EtsoTimeout) {
          return response.custom({ statusCode: 504, body: 'ETSO did not answer in time.' });
        }
        logger.warn(`ETSO unreachable at ${target.origin}: ${error}`);
        return response.custom({
          statusCode: 502,
          body: `ETSO is unreachable at ${target.origin} (wazuhIframeWidget.etsoUrl).`,
        });
      }

      if (etso.statusCode >= 400) {
        // The Wazuh dashboard wraps error responses itself and takes a
        // string message, e.g. ETSO's {"detail": "..."}.
        return response.custom({ statusCode: etso.statusCode, body: etso.body.toString('utf8') });
      }

      const headers: Record<string, string> = {};
      for (const name of PASSED_HEADERS) {
        const value = etso.headers[name];
        if (typeof value === 'string') headers[name] = value;
      }
      return response.custom({ statusCode: etso.statusCode, body: etso.body, headers });
    }
  );
}
