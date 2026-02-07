import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useRouterState } from '@tanstack/react-router';
import { BookOpen, Github, LogOut, Menu, Settings, User } from 'lucide-react';
import { useMemo, useState } from 'react';
import { BeaconIcon } from '@/components/beacon-icon';
import { LanguageToggle } from '@/components/language-toggle';
import { ThemeToggle } from '@/components/theme-toggle';
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
import * as m from '@/paraglide/messages';
import { ApiError, apiClient, queryKeys } from '@/utils/api';

type CurrentUser = {
  id: string;
  username: string;
};

async function fetchOptionalUser(): Promise<CurrentUser | null> {
  try {
    return await apiClient<CurrentUser>('/api/v1/user/me', {
      requiresAuth: false,
    });
  } catch (error) {
    // Treat "not logged in" as a normal state.
    if (error instanceof ApiError && error.status === 401) return null;
    return null;
  }
}

export function AppNavbar() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [mobileOpen, setMobileOpen] = useState(false);

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
    <header className="sticky top-0 z-50 w-full border-b border-border/70 bg-background/80 backdrop-blur supports-backdrop-filter:bg-background/70">
      <div className="container mx-auto flex h-16 items-center justify-between px-4 sm:px-6">
        <div className="flex items-center gap-2 min-w-0">
          <Link to="/" className="flex items-center gap-2 min-w-0">
            <BeaconIcon className="h-7 w-7 shrink-0 text-primary" />
            <span className="font-bold tracking-tight truncate">
              {m.app_name()}
            </span>
          </Link>
        </div>

        <div className="flex items-center gap-1 sm:gap-2">
          <Button variant="ghost" asChild className="hidden md:inline-flex">
            <Link to="/docs/$">
              <BookOpen className="h-4 w-4 mr-2" />
              {m.nav_docs()}
            </Link>
          </Button>

          <a
            href="https://github.com/Summpot/beacon_auth"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden md:inline-flex"
          >
            <Button
              variant="ghost"
              size="icon"
              aria-label={m.button_view_github()}
            >
              <Github className="h-5 w-5" />
            </Button>
          </a>

          <ThemeToggle />

          <div className="hidden sm:block">
            <LanguageToggle />
          </div>

          {canShowDesktopAuthControls ? (
            isAuthed ? (
              <div className="hidden sm:block">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" className="max-w-[16rem]">
                      <User className="h-4 w-4 mr-2" />
                      <span className="truncate">{user?.username}</span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem asChild>
                      <Link to="/profile" className="cursor-default">
                        <User className="h-4 w-4" />
                        <span>{m.button_view_profile()}</span>
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuItem asChild>
                      <Link to="/settings" className="cursor-default">
                        <Settings className="h-4 w-4" />
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
                      <LogOut className="h-4 w-4" />
                      <span>{m.nav_logout()}</span>
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            ) : (
              <div className="hidden sm:flex items-center gap-2">
                <Button variant="ghost" asChild>
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
                <Menu className="h-5 w-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="p-0">
              <SheetHeader className="border-b border-border">
                <SheetTitle className="flex items-center gap-2">
                  <BeaconIcon className="h-6 w-6 text-primary" />
                  {m.app_name()}
                </SheetTitle>
              </SheetHeader>

              <div className="p-4 flex flex-col gap-2">
                <Button variant="ghost" className="justify-start" asChild>
                  <Link to="/docs/$" onClick={() => setMobileOpen(false)}>
                    <BookOpen className="h-4 w-4 mr-2" />
                    {m.nav_docs()}
                  </Link>
                </Button>

                <a
                  href="https://github.com/Summpot/beacon_auth"
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={() => setMobileOpen(false)}
                >
                  <Button variant="ghost" className="w-full justify-start">
                    <Github className="h-4 w-4 mr-2" />
                    {m.button_view_github()}
                  </Button>
                </a>

                <div className="py-2">
                  <LanguageToggle />
                </div>

                <div className="h-px bg-border my-2" />

                {isAuthed ? (
                  <>
                    <Button variant="ghost" className="justify-start" asChild>
                      <Link to="/profile" onClick={() => setMobileOpen(false)}>
                        <User className="h-4 w-4 mr-2" />
                        {m.button_view_profile()}
                      </Link>
                    </Button>
                    <Button variant="ghost" className="justify-start" asChild>
                      <Link to="/settings" onClick={() => setMobileOpen(false)}>
                        <Settings className="h-4 w-4 mr-2" />
                        {m.nav_settings()}
                      </Link>
                    </Button>

                    <Button
                      variant="destructive"
                      className="justify-start"
                      onClick={handleLogout}
                      disabled={logoutMutation.isPending}
                    >
                      <LogOut className="h-4 w-4 mr-2" />
                      {logoutMutation.isPending
                        ? m.profile_logging_out()
                        : m.nav_logout()}
                    </Button>
                  </>
                ) : (
                  <>
                    <Button variant="ghost" className="justify-start" asChild>
                      <Link to="/login" onClick={() => setMobileOpen(false)}>
                        {m.nav_login()}
                      </Link>
                    </Button>
                    <Button className="justify-start" asChild>
                      <Link to="/register" onClick={() => setMobileOpen(false)}>
                        {m.nav_get_started()}
                      </Link>
                    </Button>
                  </>
                )}
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  );
}
