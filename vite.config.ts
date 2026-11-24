import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: 'web',
  plugins: [react()],
  build: {
    outDir: '../dist/web',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/v1': 'http://127.0.0.1:8788',
      '/mcp': 'http://127.0.0.1:8788',
      '/llms.txt': 'http://127.0.0.1:8788',
      '/healthz': 'http://127.0.0.1:8788',
    },
  },
});
