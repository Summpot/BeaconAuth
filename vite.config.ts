import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { sentryVitePlugin } from '@sentry/vite-plugin';
import tailwindcss from '@tailwindcss/vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import mdx from 'fumadocs-mdx/vite';
import { nitro } from 'nitro/vite';
import { defineConfig } from 'vite';
import tsConfigPaths from 'vite-tsconfig-paths';
import * as MdxConfig from './source.config';

export default defineConfig({
  server: {
    port: 3000,
  },

  plugins: [
    tsConfigPaths({
      projects: ['./tsconfig.json'],
    }),
    mdx(MdxConfig),
    paraglideVitePlugin({
      project: './project.inlang',
      outdir: './src/paraglide',
      outputStructure: 'message-modules',
      cookieName: 'PARAGLIDE_LOCALE',
      strategy: ['url', 'cookie', 'preferredLanguage', 'baseLocale'],
      urlPatterns: [
        {
          pattern: '/',
          localized: [
            ['en', '/en'],
            ['fr', '/fr'],
            ['de', '/de'],
            ['ja', '/ja'],
            ['zh-CN', '/zh-CN'],
            ['zh-TW', '/zh-TW'],
          ],
        },
        {
          pattern: '/docs/:path(.*)?',
          localized: [
            ['en', '/en/docs/:path(.*)?'],
            ['fr', '/fr/docs/:path(.*)?'],
            ['de', '/de/docs/:path(.*)?'],
            ['ja', '/ja/docs/:path(.*)?'],
            ['zh-CN', '/zh-CN/docs/:path(.*)?'],
            ['zh-TW', '/zh-TW/docs/:path(.*)?'],
          ],
        },
      ],
    }),
    tailwindcss(),
    tanstackStart(),
    viteReact(),
    nitro(),
    sentryVitePlugin({
      org: 'summpot',
      project: 'beaconauth',
    }),
  ],

  nitro: {
    debug: true,
    serverDir: './',
    cloudflare: {
      deployConfig: true,
      nodeCompat: true,
    },
  },

  build: {
    sourcemap: true,
  },
});
