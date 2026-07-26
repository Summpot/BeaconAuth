import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useRouterState } from '@tanstack/react-router';
import { BookOpen, Github, LogOut, Menu, Settings, User } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { BeaconIcon } from '@/components/beacon-icon';
import { LanguageToggle } from '@/components/language-toggle';
import { ThemeToggle } from '@/components/theme-toggle';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet';
import { cn } from '@/lib/utils';
import * as m from '@/paraglide/messages';
import { ApiError, apiClient, queryKeys, type UserInfo } from '@/utils/api';

async function fetchOptionalUser(): Promise<UserInfo | null> {
  try {
    return await apiClient<UserInfo>('/api/v1/user/me', {
      requiresAuth: false,
    });
  } catch (error) {
    // Treat "not logged in" as a normal state.
    if (error instanceof ApiError && error.status === 401) return null;
    return null;
  }
}

/**
 * Material Design 3 navigation drawer item: 56dp pill, active state carried by
 * the secondary-container role.
 */
function drawerItemClass(active?: boolean) {
  return cn(
    'state-layer flex h-14 items-center gap-3 rounded-full px-4 text-label-lg',
    '[&_svg]:size-6 [&_svg]:shrink-0',
    active
      ? 'bg-secondary-container text-on-secondary-container'
      : 'text-on-surface-variant',
  );
}

export function AppNavbar() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  const { data: user } = useQuery({
    queryKey: queryKeys.userMe(),
    queryFn: fetchOptionalUser,
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await apiClient('/api/v1/logout', { method: 'POST' });
    },
    onSuccess: async () => {
      queryClient.setQueryData(queryKeys.userMe(), null);
      queryClient.removeQueries({ queryKey: queryKeys.userMe() });
      await navigate({ to: '/login', replace: true });
    },
  });

  // M3 top app bars swap from `surface` to `surface-container` once content
  // scrolls beneath them.
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 0);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const isAuthed = Boolean(user);
  const canShowDesktopAuthControls = useMemo(
    () => !pathname.startsWith('/docs'),
    [pathname],
  );

  const handleLogout = () => {
    setMobileOpen(false);
    logoutMutation.mutate();
  };

  return (
    <header
      className={cn(
        'sticky top-0 z-50 w-full transition-colors duration-200 ease-standard',
        scrolled ? 'bg-surface-container shadow-level2' : 'bg-surface',
      )}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-2 px-4 sm:px-6">
        <Link
          to="/"
          className="flex min-w-0 items-center gap-3 rounded-full pr-2 focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-primary"
        >
          <BeaconIcon className="h-8 w-8 shrink-0" />
          <span className="truncate text-title-lg text-on-surface">
            {m.app_name()}
          </span>
        </Link>

        <div className="flex items-center gap-1">
          <Button variant="text" asChild className="hidden md:inline-flex">
            <Link to="/docs/$">
              <BookOpen />
              {m.nav_docs()}
            </Link>
          </Button>

          <Button
            variant="ghost"
            size="icon"
            asChild
            className="hidden md:inline-flex"
          >
            <a
              href="https://github.com/Summpot/beacon_auth"
              target="_blank"
              rel="noopener noreferrer"
              aria-label={m.button_view_github()}
            >
              <Github />
            </a>
          </Button>

          <ThemeToggle />

          <div className="hidden sm:block">
            <LanguageToggle />
          </div>

          {canShowDesktopAuthControls ? (
            isAuthed ? (
              <div className="hidden sm:block">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <button
                      type="button"
                      className="state-layer ml-1 flex max-w-64 items-center gap-2 rounded-full p-1 pr-3 text-label-lg text-on-surface focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-primary"
                    >
                      <Avatar className="size-8">
                        {user?.avatar_url ? (
                          <AvatarImage
                            src={user.avatar_url}
                            alt={user.username}
                          />
                        ) : null}
                        <AvatarFallback className="text-label-lg">
                          {user?.username.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <span className="truncate">{user?.username}</span>
                    </button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="min-w-56">
                    <DropdownMenuItem asChild>
                      <Link to="/profile" className="cursor-default">
                        <User />
                        <span>{m.button_view_profile()}</span>
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuItem asChild>
                      <Link to="/settings" className="cursor-default">
                        <Settings />
                        <span>{m.nav_settings()}</span>
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      variant="destructive"
                      onSelect={(e) => {
                        e.preventDefault();
                        handleLogout();
                      }}
                    >
                      <LogOut />
                      <span>{m.nav_logout()}</span>
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            ) : (
              <div className="ml-1 hidden items-center gap-2 sm:flex">
                <Button variant="text" asChild>
                  <Link to="/login">{m.nav_login()}</Link>
                </Button>
                <Button asChild>
                  <Link to="/register">{m.nav_get_started()}</Link>
                </Button>
              </div>
            )
          ) : null}

          <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
            <SheetTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="md:hidden"
                aria-label={m.nav_menu()}
              >
                <Menu />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="gap-0 p-3">
              <SheetHeader className="px-4 pt-3 pb-4">
                <SheetTitle className="flex items-center gap-3 text-title-md text-on-surface">
                  <BeaconIcon className="h-7 w-7" />
                  {m.app_name()}
                </SheetTitle>
              </SheetHeader>

              <nav className="flex flex-col gap-1">
                <Link
                  to="/docs/$"
                  className={drawerItemClass(pathname.startsWith('/docs'))}
                  onClick={() => setMobileOpen(false)}
                >
                  <BookOpen />
                  {m.nav_docs()}
                </Link>

                <a
                  href="https://github.com/Summpot/beacon_auth"
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={() => setMobileOpen(false)}
                  className="state-layer flex h-14 items-center gap-3 rounded-full px-4 text-label-lg text-on-surface-variant [&_svg]:size-6 [&_svg]:shrink-0"
                >
                  <Github />
                  {m.button_view_github()}
                </a>

                <div className="px-2 py-2">
                  <LanguageToggle />
                </div>

                <div className="mx-4 my-2 h-px bg-outline-variant" />

                {isAuthed ? (
                  <>
                    <Link
                      to="/profile"
                      className={drawerItemClass(
                        pathname.startsWith('/profile'),
                      )}
                      onClick={() => setMobileOpen(false)}
                    >
                      <User />
                      {m.button_view_profile()}
                    </Link>
                    <Link
                      to="/settings"
                      className={drawerItemClass(
                        pathname.startsWith('/settings'),
                      )}
                      onClick={() => setMobileOpen(false)}
                    >
                      <Settings />
                      {m.nav_settings()}
                    </Link>

                    <Button
                      variant="destructive-text"
                      className="mt-2 h-14 justify-start rounded-full px-4"
                      onClick={handleLogout}
                      disabled={logoutMutation.isPending}
                    >
                      <LogOut />
                      {logoutMutation.isPending
                        ? m.profile_logging_out()
                        : m.nav_logout()}
                    </Button>
                  </>
                ) : (
                  <div className="flex flex-col gap-2 px-2 pt-2">
                    <Button variant="outlined" asChild className="h-14">
                      <Link to="/login" onClick={() => setMobileOpen(false)}>
                        {m.nav_login()}
                      </Link>
                    </Button>
                    <Button asChild className="h-14">
                      <Link to="/register" onClick={() => setMobileOpen(false)}>
                        {m.nav_get_started()}
                      </Link>
                    </Button>
                  </div>
                )}
              </nav>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  );
}
