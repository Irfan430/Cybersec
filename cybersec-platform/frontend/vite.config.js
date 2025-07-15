import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'
import { VitePWA } from 'vite-plugin-pwa'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg}'],
        navigateFallback: 'index.html',
        navigateFallbackDenylist: [/^\/_/, /\/[^/?]+\.[^/]+$/]
      },
      manifest: {
        name: 'CyberSec Platform',
        short_name: 'CyberSec',
        description: 'AI-Powered Cybersecurity Risk Simulation Platform',
        theme_color: '#1f2937',
        background_color: '#ffffff',
        display: 'standalone',
        orientation: 'portrait-primary',
        scope: '/',
        start_url: '/',
        icons: [
          {
            src: '/icon-192x192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: '/icon-512x512.png',
            sizes: '512x512',
            type: 'image/png'
          }
        ]
      }
    })
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@components': resolve(__dirname, 'src/components'),
      '@pages': resolve(__dirname, 'src/pages'),
      '@hooks': resolve(__dirname, 'src/hooks'),
      '@services': resolve(__dirname, 'src/services'),
      '@utils': resolve(__dirname, 'src/utils'),
      '@contexts': resolve(__dirname, 'src/contexts'),
      '@assets': resolve(__dirname, 'src/assets'),
      '@styles': resolve(__dirname, 'src/styles'),
      '@types': resolve(__dirname, 'src/types'),
      '@config': resolve(__dirname, 'src/config')
    }
  },
  server: {
    port: 3000,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        secure: false
      },
      '/socket.io': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        secure: false,
        ws: true
      }
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    },
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['chart.js', 'react-chartjs-2', 'apexcharts', 'react-apexcharts', 'recharts'],
          utils: ['lodash', 'moment', 'date-fns', 'uuid'],
          ui: ['lucide-react', 'framer-motion', 'react-hot-toast']
        }
      }
    },
    chunkSizeWarningLimit: 1000
  },
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'react-query',
      'axios',
      'socket.io-client',
      'chart.js',
      'react-chartjs-2',
      'apexcharts',
      'react-apexcharts',
      'recharts',
      'lodash',
      'moment',
      'date-fns',
      'uuid',
      'js-cookie',
      'jwt-decode',
      'lucide-react',
      'framer-motion',
      'react-hot-toast',
      'react-hook-form',
      'react-select',
      'react-datepicker',
      'react-modal',
      'react-dropzone',
      'react-table',
      'react-markdown',
      'react-syntax-highlighter',
      'react-loading-skeleton',
      'react-intersection-observer',
      'react-transition-group',
      'classnames',
      'clsx',
      'tailwind-merge'
    ]
  },
  define: {
    'process.env': process.env,
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version)
  },
  css: {
    postcss: {
      plugins: [
        require('tailwindcss'),
        require('autoprefixer')
      ]
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.js'
  }
})