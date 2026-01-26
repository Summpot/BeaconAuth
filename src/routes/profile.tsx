import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import {
  CheckCircle,
  CheckCircle2,
  Gamepad2,
  Shield,
  XCircle,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardTitle,
} from '@/components/ui/card';
import { PageLoader } from '@/components/ui/page-loader';
import * as m from '@/paraglide/messages';
import { type ApiError, apiClient, queryKeys } from '../utils/api';

const searchParamsSchema = z.object({
  status: z.enum(['success', 'error']).optional(),
  message: z.string().optional(),
});

interface UserInfo {
  id: string;
  username: string;
  email: string | null;
  avatar_source: string | null;
  avatar_url: string | null;
}

async function fetchUserInfo(): Promise<UserInfo> {
  return apiClient<UserInfo>('/api/v1/user/me');
}

function ProfilePage() {
  const { status, message } = Route.useSearch();
  const [statusMessage, setStatusMessage] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);
  const navigate = useNavigate();

  const {
    data: user,
    isLoading,
    isFetching,
    error,
  } = useQuery<UserInfo, ApiError>({
    queryKey: queryKeys.userMe(),
    queryFn: fetchUserInfo,
    retry: (failureCount, err) => {
      if (err?.status === 401) return false;
      return failureCount < 1;
    },
  });

  useEffect(() => {
    if (status && message) {
      setStatusMessage({
        type: status,
        text: decodeURIComponent(message.replace(/\+/g, ' ')),
      });
      const timer = setTimeout(() => setStatusMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [status, message]);

  useEffect(() => {
    // Don't redirect on a stale cached 401 if a refetch is currently in-flight.
    if (!isFetching && error?.status === 401) {
      navigate({ to: '/login', replace: true });
    }
  }, [error, isFetching, navigate]);

  useEffect(() => {
    // If the cached user was cleared (e.g. after logout), redirect rather than rendering nothing.
    if (!isLoading && !isFetching && !error && !user) {
      navigate({ to: '/login', replace: true });
    }
  }, [error, isFetching, isLoading, navigate, user]);

  if (isLoading) {
    return (
      <PageLoader
        title={m.profile_loading()}
        icon={<BeaconIcon className="size-6 text-primary" />}
      />
    );
  }

  if (error && error.status !== 401) {
    return (
      <div className="flex items-center justify-center min-h-full p-6 bg-background">
        <div className="w-full max-w-md">
          <Card className="text-center shadow-sm border-border/70">
            <CardContent className="pt-10 pb-10">
              <div className="inline-block mb-6 p-4 rounded-full bg-destructive/10 text-destructive">
                <BeaconIcon className="w-12 h-12" />
              </div>
              <CardTitle className="text-2xl font-semibold mb-4">
                {m.profile_error_title()}
              </CardTitle>
              <CardDescription className="mb-8">
                {error.message}
              </CardDescription>
              <div className="flex flex-col gap-3">
                <Button asChild size="lg">
                  <Link to="/">{m.profile_back_home()}</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (!user) {
    return null; // Will redirect
  }

  return (
    <div className="min-h-full bg-background pb-20">
      <div className="container max-w-5xl mx-auto px-4 md:px-6 pt-12">
        {statusMessage && (
          <Alert
            variant={
              statusMessage.type === 'success' ? 'default' : 'destructive'
            }
            className={
              statusMessage.type === 'success'
                ? 'mb-8 border-border/70 bg-card/90'
                : 'mb-8'
            }
          >
            {statusMessage.type === 'success' ? (
              <CheckCircle2 className="text-chart-1" />
            ) : (
              <XCircle />
            )}
            <AlertDescription>
              <p className="font-medium text-foreground">
                {statusMessage.text}
              </p>
            </AlertDescription>
          </Alert>
        )}

        <div className="flex flex-col md:flex-row gap-8 mb-12 items-center md:items-start text-center md:text-left">
          <div className="relative group">
            <Avatar className="h-32 w-32 border border-border/70 shadow-sm">
              {user.avatar_url ? (
                <AvatarImage src={user.avatar_url} alt={user.username} />
              ) : null}
              <AvatarFallback className="bg-primary text-5xl text-primary-foreground font-bold">
                {user.username.charAt(0).toUpperCase()}
              </AvatarFallback>
            </Avatar>
            <div
              className="absolute bottom-2 right-2 w-8 h-8 bg-chart-1 rounded-full border-2 border-background flex items-center justify-center shadow-xs"
              title={m.profile_status_authenticated()}
            >
              <CheckCircle className="h-4 w-4 text-white" />
            </div>
          </div>
          <div className="flex-1 pt-4">
            <h1 className="text-3xl font-semibold tracking-tight mb-2 text-foreground">
              {user.username}
            </h1>
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-4 text-muted-foreground">
              <Badge
                variant="secondary"
                className="px-3 py-1 text-sm font-medium rounded-full"
              >
                {m.profile_user_role()}
              </Badge>
              <span className="flex items-center gap-2 text-sm font-mono bg-muted/40 px-3 py-1 rounded-full">
                {m.profile_account_id()}: {user.id}
              </span>
            </div>
          </div>
          <Button asChild size="lg" className="px-6">
            <Link to="/settings">{m.button_manage_settings()}</Link>
          </Button>
        </div>

        <div className="grid md:grid-cols-2 gap-6 mb-8">
          <Card className="border border-border/60 shadow-xs hover:shadow-sm transition-shadow bg-card">
            <CardContent className="p-8 flex items-start gap-5">
              <div className="w-12 h-12 rounded-xl bg-chart-1/15 flex items-center justify-center shrink-0 text-chart-1">
                <CheckCircle className="h-6 w-6" />
              </div>
              <div>
                <h3 className="font-semibold text-lg mb-1">
                  {m.profile_status()}
                </h3>
                <p className="text-muted-foreground mb-3 leading-relaxed">
                  {m.profile_status_verified_desc()}
                </p>
                <Badge
                  variant="outline"
                  className="text-chart-1 border-chart-1/30 bg-chart-1/10"
                >
                  {m.profile_status_authenticated()}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="border border-border/60 shadow-xs hover:shadow-sm transition-shadow bg-card">
            <CardContent className="p-8 flex items-start gap-5">
              <div className="w-12 h-12 rounded-xl bg-chart-2/15 flex items-center justify-center shrink-0 text-chart-2">
                <Gamepad2 className="h-6 w-6" />
              </div>
              <div>
                <h3 className="font-semibold text-lg mb-1">
                  {m.profile_minecraft()}
                </h3>
                <p className="text-muted-foreground mb-3 leading-relaxed">
                  {m.profile_minecraft_connected_desc()}
                </p>
                <Badge
                  variant="outline"
                  className="text-chart-2 border-chart-2/30 bg-chart-2/10"
                >
                  {m.profile_connected()}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </div>

        <Alert className="bg-card border-border shadow-sm mb-12">
          <Shield className="h-5 w-5 text-primary" />
          <AlertDescription className="ml-2">
            <h3 className="font-semibold text-foreground mb-1">
              {m.profile_secure_session_title()}
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              {m.profile_secure_session_desc()}
            </p>
          </AlertDescription>
        </Alert>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/profile')({
  component: ProfilePage,
  validateSearch: searchParamsSchema,
});
