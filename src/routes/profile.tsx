import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { CheckCircle, CheckCircle2, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardTitle,
} from '@/components/ui/card';
import { PageLoader } from '@/components/ui/page-loader';
import * as m from '@/paraglide/messages';
import {
  type ApiError,
  apiClient,
  queryKeys,
  type UserInfo,
} from '../utils/api';

const searchParamsSchema = z.object({
  status: z.enum(['success', 'error']).optional(),
  message: z.string().optional(),
});

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
      <div className="flex min-h-full items-center justify-center bg-surface p-6">
        <div className="w-full max-w-md">
          <Card className="rounded-xl text-center">
            <CardContent className="py-10">
              <div className="mb-6 inline-flex size-20 items-center justify-center rounded-full bg-error-container text-on-error-container">
                <BeaconIcon className="size-12" />
              </div>
              <CardTitle className="mb-3 text-headline-sm">
                {m.profile_error_title()}
              </CardTitle>
              <CardDescription className="mb-8 text-body-lg">
                {error.message}
              </CardDescription>
              <Button asChild size="lg">
                <Link to="/">{m.profile_back_home()}</Link>
              </Button>
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
    <div className="min-h-full bg-surface pb-20">
      <div className="mx-auto max-w-5xl px-4 pt-12 md:px-6">
        {statusMessage && (
          <Alert
            variant={
              statusMessage.type === 'success' ? 'success' : 'destructive'
            }
            className="mb-8"
          >
            {statusMessage.type === 'success' ? <CheckCircle2 /> : <XCircle />}
            <AlertDescription>
              <p className="text-title-sm">{statusMessage.text}</p>
            </AlertDescription>
          </Alert>
        )}

        <div className="mb-12 flex flex-col items-center gap-8 text-center md:flex-row md:items-start md:text-left">
          <div className="group relative">
            <Avatar className="size-32 shadow-level1">
              {user.avatar_url ? (
                <AvatarImage src={user.avatar_url} alt={user.username} />
              ) : null}
              <AvatarFallback className="text-display-sm">
                {user.username.charAt(0).toUpperCase()}
              </AvatarFallback>
            </Avatar>
            <div
              className="absolute right-1 bottom-1 flex size-9 items-center justify-center rounded-full border-4 border-surface bg-primary text-on-primary"
              title={m.profile_status_authenticated()}
            >
              <CheckCircle className="size-4" />
            </div>
          </div>

          <div className="flex-1 pt-2">
            <h1 className="mb-1 text-headline-lg text-on-surface">
              {user.username}
            </h1>
            {user.email ? (
              <p className="mb-3 text-body-lg text-on-surface-variant">
                {user.email}
              </p>
            ) : null}
            <div className="flex flex-wrap items-center justify-center gap-2 md:justify-start">
              <span className="rounded-sm bg-surface-container-high px-3 py-1.5 font-mono text-label-md text-on-surface-variant">
                {m.profile_account_id()}: {user.id}
              </span>
            </div>
          </div>

          <Button asChild size="lg">
            <Link to="/settings">{m.button_manage_settings()}</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/profile')({
  component: ProfilePage,
  validateSearch: searchParamsSchema,
});
