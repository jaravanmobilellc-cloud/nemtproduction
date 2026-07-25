import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  output: 'server',
  adapter: cloudflare({
    platformProxy: {
      enabled: true,
      // Forces the internal compiler to output structural files 
      // designed specifically for the Cloudflare Pages engine
      configPath: 'pages' 
    }
  }),
  outDir: './dist',
  build: {
    server: './dist/server',
    client: './dist/client'
  }
});