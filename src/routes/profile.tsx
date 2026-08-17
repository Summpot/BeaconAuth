import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Fingerprint,
  Gamepad2,
  KeyRound,
  Link2,
  Mail,
  Settings2,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { type OAuthProvider, ProviderIcon } from '@/components/provider-icon';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
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

interface IdentityInfo {
  id: string;
  provider: string;
  provider_user_id: string;
}

interface IdentitiesResponse {
  identities: IdentityInfo[];
  has_password: boolean;
  passkey_count: number;
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
    isLoading: userLoading,
    isFetching: userFetching,
    error: userError,
  } = useQuery<UserInfo, ApiError>({
    queryKey: queryKeys.userMe(),
    queryFn: () => apiClient<UserInfo>('/api/v1/user/me'),
    retry: false,
  });

  const { data: identities, isLoading: identitiesLoading } = useQuery({
    queryKey: ['profile', 'identities'] as const,
    queryFn: async (): Promise<IdentitiesResponse | null> => {
      try {
        return await apiClient<IdentitiesResponse>('/api/v1/identities');
      } catch {
        return null;
      }
    },
    enabled: Boolean(user),
    staleTime: 30_000,
  });

  const { data: passkeyCount } = useQuery({
    queryKey: ['profile', 'passkeys-count'] as const,
    queryFn: async (): Promise<number | null> => {
      try {
        const data = await apiClient<{ passkeys: unknown[] }>(
          '/api/v1/passkey/list',
        );
        return Array.isArray(data.passkeys) ? data.passkeys.length : 0;
      } catch {
        return null;
      }
    },
    enabled: Boolean(user),
    staleTime: 30_000,
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
    if (!userFetching && userError?.status === 401) {
      navigate({ to: '/login', replace: true });
    }
  }, [userError, userFetching, navigate]);

  useEffect(() => {
    if (!userLoading && !userFetching && !userError && !user) {
      navigate({ to: '/login', replace: true });
    }
  }, [userError, userFetching, userLoading, navigate, user]);

  if (userLoading) {
    return <ProfileSkeleton />;
  }

  if (userError && userError.status !== 401) {
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
                {userError.message}
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
    return null;
  }

  const linkedByProvider: Record<string, true> = {};
  for (const i of identities?.identities ?? []) {
    linkedByProvider[i.provider] = true;
  }
  const linkedProviderCount = Object.keys(linkedByProvider).length;
  const hasPassword = identities?.has_password ?? null;
  const effectivePasskeyCount =
    identities?.passkey_count ?? passkeyCount ?? null;
  const isSecurityLoading = identitiesLoading && identities === undefined;
  const minecraftLinked = Boolean(linkedByProvider.minecraft);
  const factors = [
    hasPassword === true,
    linkedProviderCount > 0,
    (effectivePasskeyCount ?? 0) > 0,
  ].filter(Boolean).length;

  return (
    <div className="min-h-full bg-background pb-20">
      {/* Header glow */}
      <div className="pointer-events-none absolute inset-x-0 top-[56px] h-[280px] overflow-hidden">
        <div className="absolute left-1/2 top-0 h-[420px] w-[900px] max-w-[92vw] -translate-x-1/2 rounded-full bg-primary/[0.03] blur-3xl dark:bg-primary/[0.055]" />
        <div className="absolute left-[18%] top-8 h-72 w-72 rounded-full bg-accent/35 blur-3xl dark:bg-accent/10" />
      </div>

      <div className="relative container max-w-5xl mx-auto px-4 md:px-6 pt-8 md:pt-10">
        {statusMessage && (
          <Alert
            variant={
              statusMessage.type === 'success' ? 'default' : 'destructive'
            }
            className={
              statusMessage.type === 'success'
                ? 'mb-6 border-border/70 bg-card/90'
                : 'mb-6'
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

        {/* Identity card — the anchor */}
        <Card className="overflow-hidden border-border/60 shadow-sm">
          <div className="h-1 w-full bg-gradient-to-r from-primary/60 via-primary/25 to-accent/40" />
          <CardContent className="p-6 md:p-7">
            <div className="flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
              <div className="flex gap-5 items-start">
                <div className="relative shrink-0">
                  <Avatar className="h-[84px] w-[84px] border border-border/70 shadow-sm md:h-24 md:w-24">
                    {user.avatar_url ? (
                      <AvatarImage src={user.avatar_url} alt={user.username} />
                    ) : null}
                    <AvatarFallback className="bg-primary text-primary-foreground text-3xl font-bold">
                      {user.username.charAt(0).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <span
                    className="absolute -bottom-1 -right-1 flex size-7 items-center justify-center rounded-full border-2 border-card bg-chart-1 text-white shadow-sm"
                    title={m.profile_status_authenticated()}
                    role="img"
                    aria-label={m.profile_status_authenticated()}
                  >
                    <ShieldCheck className="size-3.5" />
                  </span>
                </div>

                <div className="min-w-0 pt-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h1 className="text-[22px] font-semibold tracking-tight leading-none md:text-2xl">
                      {user.username}
                    </h1>
                    <Badge
                      variant="secondary"
                      className="gap-1.5 font-normal border-primary/15 bg-primary/[0.06] text-foreground"
                    >
                      <span className="size-1.5 rounded-full bg-chart-1" />
                      {m.profile_status_authenticated()}
                    </Badge>
                  </div>
                  {user.email ? (
                    <p className="mt-1.5 inline-flex items-center gap-1.5 text-sm text-muted-foreground">
                      <Mail className="size-3.5 opacity-70" />
                      {user.email}
                    </p>
                  ) : (
                    <p className="mt-1.5 text-sm text-muted-foreground">
                      {m.profile_no_email()}
                    </p>
                  )}

                  <div className="mt-3 flex flex-wrap gap-2">
                    <span className="inline-flex items-center gap-2 rounded-full border border-border/60 bg-muted/35 px-3 py-1 text-xs font-mono text-muted-foreground">
                      {m.profile_account_id()}: {user.id}
                    </span>
                    {user.identity_mode ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-border/60 bg-card px-3 py-1 text-xs text-muted-foreground">
                        <Gamepad2 className="size-3.5" />
                        {m.profile_identity_mode_label()}:{' '}
                        <span className="font-medium text-foreground">
                          {user.identity_mode}
                        </span>
                      </span>
                    ) : null}
                  </div>
                </div>
              </div>

              <div className="flex flex-row gap-2 md:flex-col md:items-stretch">
                <Button asChild className="flex-1 md:w-full">
                  <Link to="/settings">
                    <Settings2 className="size-4" />
                    {m.button_manage_settings()}
                  </Link>
                </Button>
                <p className="hidden md:block text-center text-xs text-muted-foreground">
                  {m.profile_manage_hint()}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Quick actions */}
        <div className="mt-6 grid gap-3 sm:grid-cols-2">
          <Card className="border-border/60 shadow-xs transition-colors hover:bg-accent/20 hover:border-border/80">
            <Link to="/settings" className="block">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm font-semibold">
                  <span className="flex size-8 items-center justify-center rounded-lg border border-border/60 bg-card">
                    <KeyRound className="size-4 text-primary" />
                  </span>
                  {m.profile_action_security_title()}
                  <ArrowRight className="ml-auto size-4 text-muted-foreground" />
                </CardTitle>
                <CardDescription className="text-[13px] leading-relaxed">
                  {m.profile_action_security_desc()}
                </CardDescription>
              </CardHeader>
            </Link>
          </Card>

          <Card className="border-border/60 shadow-xs transition-colors hover:bg-accent/20 hover:border-border/80">
            <Link to="/settings" className="block">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm font-semibold">
                  <span className="flex size-8 items-center justify-center rounded-lg border border-border/60 bg-card">
                    <Link2 className="size-4 text-primary" />
                  </span>
                  {m.profile_action_connections_title()}
                  <ArrowRight className="ml-auto size-4 text-muted-foreground" />
                </CardTitle>
                <CardDescription className="text-[13px] leading-relaxed">
                  {m.profile_action_connections_desc()}
                </CardDescription>
              </CardHeader>
            </Link>
          </Card>
        </div>

        {/* Security overview — read-only snapshot */}
        <section className="mt-8 space-y-3">
          <div className="flex items-center gap-2">
            <div className="h-7 w-1 rounded-full bg-primary/20" />
            <h2 className="text-[15px] font-semibold tracking-tight">
              {m.profile_security_overview_title()}
            </h2>
            {isSecurityLoading ? (
              <span className="ml-2 text-xs text-muted-foreground">
                {m.common_loading()}
              </span>
            ) : null}
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            {/* Password */}
            <Card className="border-border/60 shadow-xs">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center justify-between text-sm">
                  <span className="inline-flex items-center gap-2">
                    <span className="flex size-7 items-center justify-center rounded-md border border-border/60 bg-muted/40">
                      <KeyRound className="size-3.5" />
                    </span>
                    {m.settings_password_method()}
                  </span>
                  {isSecurityLoading ? (
                    <Skeleton className="h-5 w-16 rounded-full" />
                  ) : hasPassword === true ? (
                    <Badge className="bg-chart-1/10 text-chart-1 border-chart-1/20">
                      {m.settings_enabled()}
                    </Badge>
                  ) : hasPassword === false ? (
                    <Badge variant="secondary">{m.settings_not_set()}</Badge>
                  ) : (
                    <Badge variant="secondary">—</Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {hasPassword === true
                    ? m.profile_password_set_desc()
                    : hasPassword === false
                      ? m.profile_password_not_set_desc()
                      : m.profile_security_unavailable()}
                </p>
                <Button
                  asChild
                  variant="outline"
                  size="sm"
                  className="mt-3 w-full"
                >
                  <Link to="/settings">
                    {hasPassword
                      ? m.profile_go_security()
                      : m.profile_set_password()}
                  </Link>
                </Button>
              </CardContent>
            </Card>

            {/* Passkeys */}
            <Card className="border-border/60 shadow-xs">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center justify-between text-sm">
                  <span className="inline-flex items-center gap-2">
                    <span className="flex size-7 items-center justify-center rounded-md border border-border/60 bg-muted/40">
                      <Fingerprint className="size-3.5" />
                    </span>
                    {m.settings_passkeys_title()}
                  </span>
                  {isSecurityLoading ? (
                    <Skeleton className="h-5 w-12 rounded-full" />
                  ) : (
                    <Badge variant="secondary" className="font-mono">
                      {effectivePasskeyCount ?? '—'}
                    </Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {(effectivePasskeyCount ?? 0) > 0
                    ? m.profile_passkeys_some_desc({
                        count: String(effectivePasskeyCount ?? 0),
                      })
                    : effectivePasskeyCount === 0
                      ? m.profile_passkeys_none_desc()
                      : m.profile_security_unavailable()}
                </p>
                <Button
                  asChild
                  variant="outline"
                  size="sm"
                  className="mt-3 w-full"
                >
                  <Link to="/settings">{m.profile_manage_passkeys()}</Link>
                </Button>
              </CardContent>
            </Card>

            {/* Linked accounts */}
            <Card className="border-border/60 shadow-xs">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center justify-between text-sm">
                  <span className="inline-flex items-center gap-2">
                    <span className="flex size-7 items-center justify-center rounded-md border border-border/60 bg-muted/40">
                      <Link2 className="size-3.5" />
                    </span>
                    {m.settings_linked_oauth()}
                  </span>
                  {isSecurityLoading ? (
                    <Skeleton className="h-5 w-12 rounded-full" />
                  ) : (
                    <Badge variant="secondary" className="font-mono">
                      {identities ? String(linkedProviderCount) : '—'}
                    </Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                {identities && linkedProviderCount > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {Object.keys(linkedByProvider).map((p) => (
                      <span
                        key={p}
                        className="inline-flex items-center gap-1 rounded-full border border-border/60 bg-muted/40 px-2.5 py-1 text-xs"
                      >
                        <ProviderIcon
                          provider={p as OAuthProvider}
                          className="size-3"
                        />
                        {p}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    {identities
                      ? m.profile_no_linked_accounts()
                      : m.profile_security_unavailable()}
                  </p>
                )}
                <Button
                  asChild
                  variant="outline"
                  size="sm"
                  className="mt-3 w-full"
                >
                  <Link to="/settings">{m.profile_manage_connections()}</Link>
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* Strength hint */}
          {!isSecurityLoading && identities ? (
            <Card className="border-border/60 bg-card/80 shadow-xs">
              <CardContent className="px-4 py-3">
                <div className="flex items-start gap-2.5">
                  {factors >= 2 ? (
                    <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-chart-1" />
                  ) : (
                    <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-500" />
                  )}
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    {factors >= 2 ? (
                      <>
                        <span className="font-medium text-foreground">
                          {m.profile_security_good_title()}
                        </span>{' '}
                        {m.profile_security_good_desc()}
                      </>
                    ) : factors === 1 ? (
                      <>
                        <span className="font-medium text-foreground">
                          {m.profile_security_single_factor_title()}
                        </span>{' '}
                        {m.profile_security_single_factor_desc()}
                      </>
                    ) : (
                      <>
                        <span className="font-medium text-foreground">
                          {m.profile_security_none_title()}
                        </span>{' '}
                        {m.profile_security_none_desc()}
                      </>
                    )}
                  </p>
                </div>
              </CardContent>
            </Card>
          ) : null}
        </section>

        {/* Minecraft */}
        <section className="mt-8">
          <Card className="border-border/60 shadow-xs">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm">
                <span className="flex size-7 items-center justify-center rounded-md border border-border/60 bg-muted/40">
                  <Gamepad2 className="size-3.5" />
                </span>
                {m.profile_minecraft_title()}
              </CardTitle>
              <CardDescription className="text-xs">
                {m.profile_minecraft_desc()}
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between rounded-xl border border-border/60 bg-muted/20 px-4 py-3">
                <div className="flex items-center gap-2 text-sm">
                  <ProviderIcon provider="minecraft" className="size-4" />
                  <span className="font-medium">
                    {minecraftLinked
                      ? m.profile_minecraft_linked()
                      : m.profile_minecraft_not_linked()}
                  </span>
                  {minecraftLinked ? (
                    <Badge className="bg-chart-1/10 text-chart-1 border-chart-1/20">
                      {m.settings_enabled()}
                    </Badge>
                  ) : (
                    <Badge variant="secondary">{m.settings_not_set()}</Badge>
                  )}
                </div>
                <Button asChild variant="outline" size="sm">
                  <Link to="/settings">
                    {minecraftLinked
                      ? m.profile_manage_minecraft()
                      : m.profile_link_minecraft()}
                    <ArrowRight className="size-3.5" />
                  </Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </section>

        <Separator className="mt-8" />
        <p className="mt-4 text-center text-xs text-muted-foreground">
          {m.profile_footer_hint()}{' '}
          <Link to="/settings" className="underline underline-offset-4">
            {m.nav_settings()}
          </Link>
          .
        </p>
      </div>
    </div>
  );
}

function ProfileSkeleton() {
  return (
    <div className="min-h-full bg-background pb-20">
      <div className="container max-w-5xl mx-auto px-4 md:px-6 pt-8 md:pt-10">
        <Card className="overflow-hidden border-border/60">
          <div className="h-1 w-full bg-muted/60" />
          <CardContent className="p-6 md:p-7">
            <div className="flex gap-5">
              <Skeleton className="size-[84px] rounded-full md:size-24" />
              <div className="flex-1 space-y-3 pt-1">
                <Skeleton className="h-6 w-40" />
                <Skeleton className="h-4 w-56 max-w-full" />
                <Skeleton className="h-6 w-48 rounded-full" />
              </div>
            </div>
          </CardContent>
        </Card>
        <div className="mt-6 grid gap-3 sm:grid-cols-2">
          <Skeleton className="h-[88px] rounded-xl" />
          <Skeleton className="h-[88px] rounded-xl" />
        </div>
        <div className="mt-8 grid gap-3 md:grid-cols-3">
          <Skeleton className="h-[160px] rounded-xl" />
          <Skeleton className="h-[160px] rounded-xl" />
          <Skeleton className="h-[160px] rounded-xl" />
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/profile')({
  component: ProfilePage,
  validateSearch: searchParamsSchema,
});
