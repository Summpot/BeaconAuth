import { createRootRoute, Outlet } from '@tanstack/react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import { ThemeProvider } from '@/components/theme-provider';
import { ThemeToggle } from '@/components/theme-toggle';

const RootLayout = () => {
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
      })
  );

  return (
    <ThemeProvider defaultTheme="system" storageKey="beaconauth-ui-theme">
      <QueryClientProvider client={queryClient}>
        <div className="min-h-screen bg-background text-foreground relative">
          {/* Theme toggle in top right corner */}
          <div className="fixed top-4 right-4 z-50">
            <ThemeToggle />
          </div>
          <Outlet />
        </div>
      </QueryClientProvider>
    </ThemeProvider>
  );
};

export const Route = createRootRoute({ component: RootLayout });
