// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Replace 'REPO-NAME' with your actual GitHub repository name
  base: '/vcryptolab/',
  
  // --- VITEST CONFIGURATION ADDED ---
  test: {
    // Enables global test APIs (describe, test, etc.) so they don't need to be imported
    globals: true,
    // Uses jsdom environment to simulate browser APIs (like crypto.subtle, TextEncoder/Decoder)
    environment: 'jsdom',
    // Specifies the location of the test files
    include: ['src/**/*.test.js'],
  },
})