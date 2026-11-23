import { CoreSetup, Logger, Plugin, PluginInitializerContext } from '../../../src/core/server';
import { WazuhIframeConfig } from './config';
import { registerEtsoProxyRoutes } from './routes/etso_proxy';

export class WazuhIframeServerPlugin implements Plugin {
  private readonly logger: Logger;
  // The config observable emits on subscription, before setup runs any route.
  private config: WazuhIframeConfig = { etsoUrl: 'http://127.0.0.1:8000' };

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
    initializerContext.config.create<WazuhIframeConfig>().subscribe((config) => {
      this.config = config;
    });
  }

  public setup(core: CoreSetup): void {
    registerEtsoProxyRoutes(
      core.http.createRouter(),
      core.http.basePath,
      () => this.config.etsoUrl,
      this.logger
    );
  }

  public start(): void {}
  public stop(): void {}
}
