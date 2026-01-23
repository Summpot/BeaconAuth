/// <reference types="vite/client" />
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createRootRoute,
  HeadContent,
  Outlet,
  Scripts,
  useRouterState,
} from '@tanstack/react-router';
import { defineI18nUI } from 'fumadocs-ui/i18n';
import { RootProvider } from 'fumadocs-ui/provider/tanstack';
import { type ReactNode, useState } from 'react';
import { AppNavbar } from '@/components/app-navbar';
import { ThemeProvider } from '@/components/theme-provider';
import { i18n } from '@/lib/i18n';
import { AnimatePresence, MotionConfig, motion } from '@/lib/motion';
import {
  getLocale,
  type Locale,
  locales,
  setLocale,
} from '@/paraglide/runtime';
import appCss from '../styles.css?url';

const { provider } = defineI18nUI(i18n, {
  translations: {
    'zh-CN': {
      displayName: 'Chinese',
      search: 'Translated Content',
    },
    en: {
      displayName: 'English',
    },
  },
});

function RootComponent() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60 * 1000, // 1 minute
            retry: 1,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );

  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const showNavbar = !pathname.startsWith('/docs');

  return (
    <RootDocument>
      <ThemeProvider defaultTheme="system" storageKey="beaconauth-ui-theme">
        <QueryClientProvider client={queryClient}>
          <MotionConfig reducedMotion="user">
            <div className="min-h-screen bg-background text-foreground relative flex flex-col">
              {showNavbar ? <AppNavbar /> : null}
              <main className="flex-1">
                <AnimatePresence mode="wait" initial={false}>
                  <motion.div
                    // Keyed by pathname so route changes animate.
                    key={pathname}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.18, ease: 'easeOut' }}
                  >
                    <Outlet />
                  </motion.div>
                </AnimatePresence>
              </main>
            </div>
          </MotionConfig>
        </QueryClientProvider>
      </ThemeProvider>
    </RootDocument>
  );
}

function RootDocument({ children }: Readonly<{ children: ReactNode }>) {
  const lang = getLocale();
  const i18nProps = provider(lang);
  i18nProps.onLocaleChange = (locale) => {
    if ((locales as readonly string[]).includes(locale)) {
      setLocale(locale as Locale);
    }
  };
  return (
    <html lang={lang}>
      <head>
        <HeadContent />
      </head>
      <body>
        <RootProvider i18n={i18nProps}>{children}</RootProvider>
        <Scripts />
      </body>
    </html>
  );
}

export const Route = createRootRoute({
  component: RootComponent,
  head: () => ({
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'BeaconAuth' },
    ],
    links: [{ rel: 'stylesheet', href: appCss }],
  }),
});
