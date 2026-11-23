import React from 'react';
import { EuiPage, EuiPageBody, EuiPageContent } from '@elastic/eui';

// ETSO's dashboard, fetched from ETSO by this plugin's server side
// (server/routes/etso_proxy.ts): same origin as Wazuh, so no certificate or
// port of its own, and behind the Wazuh login. basePath is the dashboard's
// server.basePath, empty unless one is configured.
export const etsoDashboardUrl = (basePath: string, darkMode: boolean): string =>
  `${basePath}/api/etso/dashboard/?theme=${darkMode ? 'dark' : 'light'}`;

export const WazuhIframeApp = ({ basePath, darkMode }: { basePath: string; darkMode: boolean }) => {
  const targetUrl = etsoDashboardUrl(basePath, darkMode);

  return (
    <EuiPage paddingSize="none" style={{ height: '100vh', width: '100%', background: 'transparent' }}>
      <EuiPageBody>
        <EuiPageContent paddingSize="none" hasShadow={false} style={{ height: '100%', width: '100%' }}>
          <iframe
            src={targetUrl}
            title="ETSO vulnerability priorities"
            width="100%"
            height="100%"
            frameBorder="0"
            // allow-same-origin: without it the frame's requests carry no Wazuh
            // session, and the route refuses them. It also means the page runs
            // with the viewer's Wazuh session, so its escaping of indexer data
            // protects Wazuh too.
            // allow-popups-to-escape-sandbox: the dashboard's NVD, CVE.org and
            // IoV server links open in new tabs, which must not inherit the sandbox.
            sandbox="allow-forms allow-modals allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin allow-scripts"
            style={{
              border: 'none',
              width: '100%',
              height: 'calc(100vh - 48px)',
              display: 'block',
            }}
          />
        </EuiPageContent>
      </EuiPageBody>
    </EuiPage>
  );
};
