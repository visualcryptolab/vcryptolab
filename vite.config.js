// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.js',
  },
  // Replace 'REPO-NAME' with your actual GitHub repository name
  base: '/vcryptolab/',
  server: {
    host: true,
    port: 5173,
    strictPort: true,
  }
})