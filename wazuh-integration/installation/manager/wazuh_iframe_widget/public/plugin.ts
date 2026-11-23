import { CoreSetup, CoreStart, Plugin } from '../../../src/core/public';

export class WazuhIframePlugin implements Plugin {
  constructor(initializerContext: any) {}

  public setup(core: CoreSetup): void {
    core.application.register({
      id: 'wazuhIframeWidget',
      title: 'IoV Dashboard',
      category: {
        id: 'wazuh',
        label: 'Wazuh',
        order: 100,
      },
      async mount(params) {
        const { renderApp } = await import('./application');
        return renderApp(core, params);
      },
    });
  }

  public start(core: CoreStart): void {}
  public stop(): void {}
}
