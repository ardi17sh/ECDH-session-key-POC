import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  // Browser talks to one origin (the dev server); /api goes to the Express app.
  server: { host: true, proxy: { '/api': 'http://localhost:3001' } },
})
