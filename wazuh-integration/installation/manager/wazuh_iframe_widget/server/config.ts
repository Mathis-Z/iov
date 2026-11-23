import { schema, TypeOf } from '@osd/config-schema';

// opensearch_dashboards.yml:
//   wazuhIframeWidget.etsoUrl: http://127.0.0.1:8000
// Where the Wazuh dashboard's server reaches ETSO. Only that server talks to
// it, so it is plain HTTP and need not be reachable from browsers.
export const configSchema = schema.object({
  etsoUrl: schema.string({ defaultValue: 'http://127.0.0.1:8000' }),
});

export type WazuhIframeConfig = TypeOf<typeof configSchema>;
