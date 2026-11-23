import { PluginConfigDescriptor, PluginInitializerContext } from '../../../src/core/server';
import { configSchema, WazuhIframeConfig } from './config';
import { WazuhIframeServerPlugin } from './plugin';

export const config: PluginConfigDescriptor<WazuhIframeConfig> = {
  schema: configSchema,
};

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhIframeServerPlugin(initializerContext);
}
