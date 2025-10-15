// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Replace 'REPO-NAME' with your actual GitHub repository name
  base: '/vcryptolab/', 
})