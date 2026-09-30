import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  build: {
    outDir: '../static/react-dist',
    emptyOutDir: true,
    lib: {
      entry: path.resolve(import.meta.dirname, 'src/main.jsx'),
      name: 'SentinelScanReact',
      formats: ['iife'],
      fileName: () => 'main.js',
    },
    rollupOptions: {
      output: {
        assetFileNames: 'main.[ext]',
      },
    },
  },
})
