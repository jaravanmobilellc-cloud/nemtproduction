import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  output: 'server',
  adapter: cloudflare({
    platformProxy: {
      enabled: true
    }
  }),
  // Explicitly set the output folders to align with the routing expectations
  outDir: './dist',
  build: {
    server: './dist/server',
    client: './dist/client'
  }
});