import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/insights/',
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8100'
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: true
  }
});
