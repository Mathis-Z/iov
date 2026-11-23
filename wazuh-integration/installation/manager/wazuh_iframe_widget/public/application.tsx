import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreSetup } from '../../../src/core/public';
import { WazuhIframeApp } from './components/app';

export const renderApp = (core: CoreSetup, { element }: AppMountParameters) => {
  // Wazuh's own dark-mode setting; the iframe cannot read it itself.
  const darkMode = Boolean(core.uiSettings.get('theme:darkMode'));
  ReactDOM.render(
    <WazuhIframeApp basePath={core.http.basePath.get()} darkMode={darkMode} />,
    element
  );

  return () => {
    ReactDOM.unmountComponentAtNode(element);
  };
};
