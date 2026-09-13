import { createFileRoute, Link } from '@tanstack/react-router';
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Gamepad2,
  Home,
  Loader2,
  XCircle,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { getErrorMessage } from '@/lib/errors';
import * as m from '@/paraglide/messages';
import { apiClient, type UserInfo } from '../../utils/api';

const searchParamsSchema = z.object({
  token: z.string().optional(),
});

interface VerifiedTicket {
  uuid: string;
  username: string;
  expires_at: number;
}

function MinecraftLinkPage() {
  const { token } = Route.useSearch();
  const [loading, setLoading] = useState(true);
  const [confirming, setConfirming] = useState(false);
  const [ticket, setTicket] = useState<VerifiedTicket | null>(null);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    let isMounted = true;

    const init = async () => {
      if (!token) {
        if (isMounted) {
          setError(m.link_minecraft_invalid_token());
          setLoading(false);
        }
        return;
      }

      try {
        // Fetch current user if session exists
        try {
          const userData = await apiClient<UserInfo>('/api/v1/user/me', {
            requiresAuth: false,
          });
          if (isMounted) {
            setUser(userData);
          }
        } catch {
          // User is unauthenticated, which is fine at this stage
        }

        // Verify ticket
        const ticketData = await apiClient<VerifiedTicket>(
          '/api/v1/minecraft/link/verify',
          {
            method: 'POST',
            requiresAuth: false,
            body: { token },
          },
        );

        if (isMounted) {
          setTicket(ticketData);
        }
      } catch (err) {
        if (isMounted) {
          setError(getErrorMessage(err, m.link_minecraft_invalid_token()));
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    init();

    return () => {
      isMounted = false;
    };
  }, [token]);

  const handleConfirm = async () => {
    if (!token) return;
    setConfirming(true);
    try {
      await apiClient('/api/v1/minecraft/link/confirm', {
        method: 'POST',
        body: { token },
      });
      setSuccess(true);
      toast.success(m.link_minecraft_success());
      setTimeout(() => {
        window.location.href = '/settings';
      }, 1200);
    } catch (err) {
      toast.error(getErrorMessage(err));
      setConfirming(false);
    }
  };

  const minutesRemaining = ticket
    ? Math.max(0, Math.round((ticket.expires_at - Date.now() / 1000) / 60))
    : 0;

  return (
    <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center p-4">
      <Card className="w-full max-w-md border-border/70 shadow-lg">
        <CardHeader className="text-center pb-4">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
            {success ? (
              <CheckCircle2 className="h-8 w-8 text-green-500" />
            ) : error ? (
              <XCircle className="h-8 w-8 text-destructive" />
            ) : (
              <Gamepad2 className="h-8 w-8" />
            )}
          </div>
          <CardTitle className="text-2xl font-bold">
            {m.link_minecraft_title()}
          </CardTitle>
          <CardDescription>{m.link_minecraft_desc()}</CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-8 space-y-3 text-muted-foreground">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <p className="text-sm">{m.common_loading()}</p>
            </div>
          ) : error ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : success ? (
            <div className="flex flex-col items-center justify-center py-6 space-y-2 text-center">
              <p className="font-semibold text-green-600 dark:text-green-400">
                {m.link_minecraft_success()}
              </p>
              <p className="text-xs text-muted-foreground">
                {m.oauth_complete_subtitle_settings()}
              </p>
            </div>
          ) : ticket ? (
            <div className="space-y-4">
              {/* Profile showcase card */}
              <div className="flex items-center gap-4 rounded-xl border border-border/70 bg-card/80 p-4">
                <Avatar className="h-16 w-16 rounded-xl border shadow-sm">
                  <AvatarImage
                    src={`https://mc-heads.net/avatar/${ticket.uuid}/64`}
                    alt={ticket.username}
                  />
                  <AvatarFallback className="rounded-xl font-bold text-lg">
                    {ticket.username.slice(0, 2).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-lg font-bold truncate">
                      {ticket.username}
                    </h3>
                    <Badge variant="outline" className="text-xs font-mono">
                      Mojang
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground font-mono break-all">
                    {ticket.uuid}
                  </p>
                  <p className="text-xs text-muted-foreground/80 mt-1">
                    {m.link_minecraft_expires_in({ minutes: minutesRemaining })}
                  </p>
                </div>
              </div>

              {/* Status or user binding target */}
              {user ? (
                <div className="rounded-xl border border-primary/20 bg-primary/5 p-4 text-sm text-foreground">
                  <p className="font-medium">
                    {m.link_minecraft_target_user({ username: user.username })}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {m.settings_minecraft_identity_desc()}
                  </p>
                </div>
              ) : (
                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    {m.link_minecraft_login_required()}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          ) : null}
        </CardContent>

        <CardFooter className="flex flex-col gap-2 pt-2">
          {ticket &&
            !success &&
            !error &&
            (user ? (
              <Button
                onClick={handleConfirm}
                disabled={confirming}
                className="w-full gap-2"
              >
                {confirming ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Gamepad2 className="h-4 w-4" />
                )}
                {m.link_minecraft_confirm_btn()}
              </Button>
            ) : (
              <div className="flex w-full gap-2">
                <Button asChild className="flex-1">
                  <Link
                    to="/login"
                    search={{
                      redirect: `/link/minecraft?token=${encodeURIComponent(token ?? '')}`,
                    }}
                  >
                    {m.nav_login()}
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Link>
                </Button>
                <Button asChild variant="outline" className="flex-1">
                  <Link to="/register">{m.button_create_account()}</Link>
                </Button>
              </div>
            ))}

          <Button
            asChild
            variant="ghost"
            className="w-full text-muted-foreground"
          >
            <Link to={user ? '/settings' : '/'}>
              <Home className="mr-2 h-4 w-4" />
              {m.link_minecraft_cancel_btn()}
            </Link>
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}

export const Route = createFileRoute('/link/minecraft')({
  validateSearch: (search) => searchParamsSchema.parse(search),
  component: MinecraftLinkPage,
});
