import { PluginInitializerContext } from '../../../src/core/public';
import { WazuhIframePlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhIframePlugin(initializerContext);
}

export { WazuhIframePlugin as Plugin };
