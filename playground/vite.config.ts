import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'node:url';

// Reuse the EXACT audited protocol code from ../reference (built to dist).
const engine = fileURLToPath(new URL('../reference/dist/index.js', import.meta.url));

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@engine': engine } },
  server: { open: true, fs: { allow: ['..'] } },
});
