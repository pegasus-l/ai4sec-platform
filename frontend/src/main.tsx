import './styles/ai4sec-styles.css';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { Providers } from './app/providers';
import { App } from './app/App';
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Providers>
      <App />
    </Providers>
  </React.StrictMode>
);
