import {
  type PublicKeyCredentialCreationOptionsJSON,
  startRegistration,
} from '@simplewebauthn/browser';
import { useForm } from '@tanstack/react-form';
import { createFileRoute, Link } from '@tanstack/react-router';
import {
  CheckCircle2,
  Key,
  Lightbulb,
  Loader2,
  Plus,
  Trash2,
  X,
  XCircle,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { FormTextField } from '@/components/form-text-field';
import {
  OAUTH_PROVIDERS,
  type OAuthProvider,
  ProviderIcon,
  providerLabel,
} from '@/components/provider-icon';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PageLoader } from '@/components/ui/page-loader';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { getErrorMessage } from '@/lib/errors';
import * as m from '@/paraglide/messages';
import { apiClient, type ServerConfig, type UserInfo } from '../utils/api';

const PROVIDER_OAUTH_FLAG = {
  github: 'github_oauth',
  google: 'google_oauth',
  microsoft: 'microsoft_oauth',
} as const satisfies Record<OAuthProvider, keyof ServerConfig>;

const AVATAR_SOURCE_LABELS: Record<OAuthProvider, () => string> = {
  github: m.settings_avatar_source_github,
  google: m.settings_avatar_source_google,
  microsoft: m.settings_avatar_source_microsoft,
};

const LINK_PROVIDER_LABELS: Record<OAuthProvider, () => string> = {
  github: m.settings_link_github,
  google: m.settings_link_google,
  microsoft: m.settings_link_microsoft,
};

const makePasswordChangeSchema = () =>
  z
    .object({
      currentPassword: z
        .string()
        .min(1, m.settings_validation_current_password_required()),
      newPassword: z
        .string()
        .min(6, m.settings_validation_password_min_length({ min: 6 })),
      confirmPassword: z
        .string()
        .min(1, m.settings_validation_confirm_password_required()),
    })
    .refine((data) => data.newPassword === data.confirmPassword, {
      message: m.settings_validation_passwords_dont_match(),
      path: ['confirmPassword'],
    });

const makePasswordSetSchema = () =>
  z
    .object({
      newPassword: z
        .string()
        .min(6, m.settings_validation_password_min_length({ min: 6 })),
      confirmPassword: z
        .string()
        .min(1, m.settings_validation_confirm_password_required()),
    })
    .refine((data) => data.newPassword === data.confirmPassword, {
      message: m.settings_validation_passwords_dont_match(),
      path: ['confirmPassword'],
    });

const makeUsernameChangeSchema = () =>
  z.object({
    username: z
      .string()
      .trim()
      .min(3, m.settings_validation_username_min_length({ min: 3 }))
      .max(16, m.settings_validation_username_max_length({ max: 16 }))
      .regex(/^[A-Za-z0-9_]+$/, m.settings_validation_username_invalid_chars()),
  });

const profileSchema = z.object({
  email: z.string(),
  avatar_source: z.enum(['', 'github', 'google', 'microsoft', 'gravatar']),
});

type ProfileData = z.infer<typeof profileSchema>;

interface PasskeyInfo {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

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

function SettingsPage() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [identities, setIdentities] = useState<IdentitiesResponse | null>(null);
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);
  const [showPasskeyModal, setShowPasskeyModal] = useState(false);
  const [passkeyName, setPasskeyName] = useState('');

  const hasPassword = identities?.has_password ?? true;
  const linkedProviders = new Set(
    (identities?.identities ?? []).map((i) => i.provider),
  );
  const enabledProviders = OAUTH_PROVIDERS.filter(
    (p) => config?.[PROVIDER_OAUTH_FLAG[p]],
  );
  const linkableProviders = enabledProviders.filter(
    (p) => !linkedProviders.has(p),
  );

  const refreshIdentities = async () => {
    try {
      const identitiesData =
        await apiClient<IdentitiesResponse>('/api/v1/identities');
      setIdentities(identitiesData);
    } catch (error) {
      console.error('Failed to refresh identities', error);
    }
  };

  const passwordChangeSchema = makePasswordChangeSchema();
  const passwordSetSchema = makePasswordSetSchema();
  const usernameChangeSchema = makeUsernameChangeSchema();

  const changePasswordForm = useForm({
    defaultValues: {
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    },
    validators: {
      onChange: passwordChangeSchema,
      onSubmit: passwordChangeSchema,
    },
    onSubmit: async ({ value, formApi }) => {
      try {
        await apiClient('/api/v1/user/change-password', {
          method: 'POST',
          body: {
            current_password: value.currentPassword,
            new_password: value.newPassword,
          },
        });
        setMessage({
          type: 'success',
          text: m.settings_success_password_changed(),
        });
        formApi.reset();
        await refreshIdentities();
      } catch (error) {
        setMessage({
          type: 'error',
          text: getErrorMessage(
            error,
            m.settings_error_failed_connect_server(),
          ),
        });
      }
    },
  });

  const setPasswordForm = useForm({
    defaultValues: {
      newPassword: '',
      confirmPassword: '',
    },
    validators: {
      onChange: passwordSetSchema,
      onSubmit: passwordSetSchema,
    },
    onSubmit: async ({ value, formApi }) => {
      try {
        await apiClient('/api/v1/user/change-password', {
          method: 'POST',
          body: { current_password: '', new_password: value.newPassword },
        });
        setMessage({
          type: 'success',
          text: m.settings_success_password_set(),
        });
        formApi.reset();
        await refreshIdentities();
      } catch (error) {
        setMessage({
          type: 'error',
          text: getErrorMessage(
            error,
            m.settings_error_failed_connect_server(),
          ),
        });
      }
    },
  });

  const changeUsernameForm = useForm({
    defaultValues: { username: '' },
    validators: {
      onChange: usernameChangeSchema,
      onSubmit: usernameChangeSchema,
    },
    onSubmit: async ({ value, formApi }) => {
      try {
        const result = await apiClient<{ success: boolean; username: string }>(
          '/api/v1/user/change-username',
          {
            method: 'POST',
            body: { username: value.username },
          },
        );

        setUser((prev) =>
          prev ? { ...prev, username: result.username } : prev,
        );
        setMessage({
          type: 'success',
          text: m.settings_success_username_updated(),
        });
        formApi.reset({ username: result.username });
      } catch (error) {
        setMessage({
          type: 'error',
          text: getErrorMessage(
            error,
            m.settings_error_failed_update_username(),
          ),
        });
      }
    },
  });

  const profileForm = useForm({
    defaultValues: { email: '', avatar_source: '' },
    validators: {
      onChange: profileSchema,
      onSubmit: profileSchema,
    },
    onSubmit: async ({ value }) => {
      try {
        await apiClient('/api/v1/user/profile', {
          method: 'POST',
          body: {
            email: value.email,
            avatar_source: value.avatar_source,
          },
        });

        const userData = await apiClient<UserInfo>('/api/v1/user/me');
        setUser(userData);
        setMessage({
          type: 'success',
          text: m.settings_success_profile_updated(),
        });
      } catch (error) {
        setMessage({
          type: 'error',
          text: getErrorMessage(
            error,
            m.settings_error_failed_update_profile(),
          ),
        });
      }
    },
  });

  useEffect(() => {
    if (user) {
      changeUsernameForm.reset({ username: user.username });
      profileForm.reset({
        email: user.email ?? '',
        avatar_source:
          user.avatar_source === 'github' ||
          user.avatar_source === 'google' ||
          user.avatar_source === 'microsoft' ||
          user.avatar_source === 'gravatar'
            ? user.avatar_source
            : '',
      });
    }
  }, [user, changeUsernameForm, profileForm]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [userData, passkeysData, identitiesData, configData] =
          await Promise.all([
            apiClient<UserInfo>('/api/v1/user/me'),
            apiClient<{ passkeys: PasskeyInfo[] }>('/api/v1/passkey/list'),
            apiClient<IdentitiesResponse>('/api/v1/identities'),
            apiClient<ServerConfig>('/api/v1/config', { requiresAuth: false }),
          ]);

        setUser(userData);
        setPasskeys(passkeysData.passkeys || []);
        setIdentities(identitiesData);
        setConfig(configData);
      } catch (error) {
        console.error('Failed to load settings data', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const handleUnlinkIdentity = async (id: string) => {
    if (!confirm(m.alert_confirm_unlink())) return;
    try {
      await apiClient(`/api/v1/identities/${id}`, { method: 'DELETE' });
      setMessage({
        type: 'success',
        text: m.settings_success_login_method_unlinked(),
      });
      await refreshIdentities();
    } catch (error) {
      setMessage({
        type: 'error',
        text: getErrorMessage(
          error,
          m.settings_error_failed_unlink_login_method(),
        ),
      });
    }
  };

  const handleOAuthLink = async (provider: OAuthProvider) => {
    try {
      const result = await apiClient<{ authorizationUrl?: string }>(
        '/api/v1/oauth/link/start',
        {
          method: 'POST',
          body: { provider, challenge: '', redirect_port: 0 },
        },
      );
      if (result.authorizationUrl) {
        window.location.href = result.authorizationUrl;
      }
    } catch (error) {
      setMessage({
        type: 'error',
        text: getErrorMessage(
          error,
          m.settings_error_failed_start_oauth_link_flow(),
        ),
      });
    }
  };

  const handlePasskeyModalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = passkeyName.trim();
    if (!name) {
      setMessage({
        type: 'error',
        text: m.settings_error_passkey_name_required(),
      });
      return;
    }
    try {
      const data = await apiClient<{
        creation_options: { publicKey: PublicKeyCredentialCreationOptionsJSON };
      }>('/api/v1/passkey/register/start', { method: 'POST', body: { name } });
      const credential = await startRegistration({
        optionsJSON: data.creation_options.publicKey,
      });
      await apiClient('/api/v1/passkey/register/finish', {
        method: 'POST',
        body: { credential, name },
      });
      setMessage({
        type: 'success',
        text: m.settings_success_passkey_registered(),
      });
      setShowPasskeyModal(false);
      setPasskeyName('');
      const passkeysData = await apiClient<{ passkeys: PasskeyInfo[] }>(
        '/api/v1/passkey/list',
      );
      setPasskeys(passkeysData.passkeys || []);
    } catch (error) {
      console.error('Passkey registration failed:', error);
      setMessage({
        type: 'error',
        text: m.settings_error_register_passkey_failed({
          error: getErrorMessage(error, m.settings_error_unknown_error()),
        }),
      });
      setShowPasskeyModal(false);
      setPasskeyName('');
    }
  };

  const handleDeletePasskey = async (id: string, name: string) => {
    if (!confirm(m.alert_confirm_delete_passkey({ name }))) return;
    try {
      await apiClient(`/api/v1/passkey/${id}`, { method: 'DELETE' });
      setMessage({
        type: 'success',
        text: m.settings_success_passkey_deleted(),
      });
      setPasskeys(passkeys.filter((p) => p.id !== id));
    } catch (error) {
      setMessage({
        type: 'error',
        text: m.settings_error_delete_passkey_failed({
          error: getErrorMessage(error, m.settings_error_unknown_error()),
        }),
      });
    }
  };

  if (loading) {
    return (
      <PageLoader
        title={m.profile_loading()}
        icon={<BeaconIcon className="size-6 text-primary" />}
      />
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-full p-4 bg-background">
        <div className="w-full max-w-md">
          <Card className="text-center shadow-sm border-border/70">
            <CardContent className="pt-8 pb-8">
              <div className="inline-block mb-6 text-muted-foreground opacity-50">
                <BeaconIcon className="w-16 h-16" />
              </div>
              <CardTitle className="text-2xl font-semibold mb-4">
                {m.settings_not_authenticated()}
              </CardTitle>
              <CardDescription className="mb-8">
                {m.settings_login_required()}
              </CardDescription>
              <Button asChild size="lg">
                <Link to="/login">{m.settings_sign_in()}</Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-full bg-background pb-20">
      <div className="container max-w-5xl mx-auto px-4 md:px-6 pt-12">
        <div className="mb-10">
          <h1 className="text-3xl font-semibold tracking-tight mb-2">
            {m.settings_title()}
          </h1>
          <p className="text-muted-foreground text-lg">
            {m.settings_subtitle({ username: user.username })}
          </p>
        </div>

        {message && (
          <Alert
            variant={message.type === 'success' ? 'default' : 'destructive'}
            className={
              message.type === 'success'
                ? 'mb-8 border-border/70 bg-card/90'
                : 'mb-8'
            }
          >
            {message.type === 'success' ? (
              <CheckCircle2 className="text-chart-1" />
            ) : (
              <XCircle />
            )}
            <AlertDescription className="flex items-center justify-between gap-4">
              <p className="font-medium text-foreground">{message.text}</p>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0"
                onClick={() => setMessage(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </AlertDescription>
          </Alert>
        )}

        <div className="grid gap-8">
          <section className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-8 w-1 bg-primary/20 rounded-full" />
              <h2 className="text-xl font-bold">
                {m.settings_profile_title()}
              </h2>
            </div>

            <Card className="border border-border/60 shadow-xs">
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  event.stopPropagation();
                  void profileForm.handleSubmit();
                }}
              >
                <profileForm.Subscribe
                  selector={(state) =>
                    [state.isSubmitting, state.values.email] as const
                  }
                >
                  {([isSubmitting, email]) => (
                    <>
                      <CardContent className="p-6 space-y-6">
                        <p className="text-muted-foreground text-sm">
                          {m.settings_profile_desc()}
                        </p>

                        <div className="flex flex-col sm:flex-row gap-6 items-start">
                          <div className="flex items-center gap-4">
                            <Avatar className="h-16 w-16 border border-border">
                              {user.avatar_url ? (
                                <AvatarImage
                                  src={user.avatar_url}
                                  alt={user.username}
                                />
                              ) : null}
                              <AvatarFallback className="bg-primary text-primary-foreground font-semibold">
                                {user.username.charAt(0).toUpperCase()}
                              </AvatarFallback>
                            </Avatar>
                            <div>
                              <div className="font-semibold">
                                {user.username}
                              </div>
                              <div className="text-xs text-muted-foreground font-mono">
                                {user.id}
                              </div>
                            </div>
                          </div>

                          <div className="flex-1 space-y-5">
                            <profileForm.Field name="email">
                              {(field) => (
                                <FormTextField
                                  field={field}
                                  label={m.settings_email_label()}
                                  labelAdornment={
                                    <Tooltip>
                                      <TooltipTrigger asChild>
                                        <Button
                                          type="button"
                                          variant="ghost"
                                          size="icon"
                                          className="h-7 w-7"
                                          aria-label={m.aria_email_info()}
                                        >
                                          <Lightbulb className="h-4 w-4 text-muted-foreground" />
                                        </Button>
                                      </TooltipTrigger>
                                      <TooltipContent>
                                        {m.settings_email_tooltip()}
                                      </TooltipContent>
                                    </Tooltip>
                                  }
                                  placeholder={m.settings_email_placeholder()}
                                  disabled={isSubmitting}
                                />
                              )}
                            </profileForm.Field>

                            <profileForm.Field name="avatar_source">
                              {(field) => (
                                <div className="space-y-3">
                                  <Label>
                                    {m.settings_avatar_source_label()}
                                  </Label>
                                  <RadioGroup
                                    value={field.state.value}
                                    onValueChange={(value) =>
                                      field.handleChange(
                                        value as ProfileData['avatar_source'],
                                      )
                                    }
                                    className="grid gap-3"
                                  >
                                    <div className="flex items-center justify-between rounded-xl border border-border/60 p-4 bg-card/80">
                                      <div className="flex items-center gap-3">
                                        <RadioGroupItem
                                          value=""
                                          id="avatar_auto"
                                        />
                                        <Label
                                          htmlFor="avatar_auto"
                                          className="cursor-pointer"
                                        >
                                          {m.settings_avatar_source_auto()}
                                        </Label>
                                      </div>
                                    </div>

                                    {enabledProviders.map((p) => (
                                      <div
                                        key={p}
                                        className="flex items-center justify-between rounded-xl border border-border/60 p-4 bg-card/80"
                                      >
                                        <div className="flex items-center gap-3">
                                          <RadioGroupItem
                                            value={p}
                                            id={`avatar_${p}`}
                                            disabled={!linkedProviders.has(p)}
                                          />
                                          <Label
                                            htmlFor={`avatar_${p}`}
                                            className="cursor-pointer flex items-center gap-2"
                                          >
                                            <ProviderIcon
                                              provider={p}
                                              className="h-4 w-4"
                                            />
                                            {AVATAR_SOURCE_LABELS[p]()}
                                          </Label>
                                        </div>
                                        {!linkedProviders.has(p) && (
                                          <Badge variant="secondary">
                                            {m.settings_avatar_requires_linked()}
                                          </Badge>
                                        )}
                                      </div>
                                    ))}

                                    <div className="flex items-center justify-between rounded-xl border border-border/60 p-4 bg-card/80">
                                      <div className="flex items-center gap-3">
                                        <RadioGroupItem
                                          value="gravatar"
                                          id="avatar_gravatar"
                                          disabled={email.trim().length === 0}
                                        />
                                        <Label
                                          htmlFor="avatar_gravatar"
                                          className="cursor-pointer"
                                        >
                                          {m.settings_avatar_source_gravatar()}
                                        </Label>
                                      </div>
                                      {email.trim().length === 0 && (
                                        <Badge variant="secondary">
                                          {m.settings_avatar_requires_email()}
                                        </Badge>
                                      )}
                                    </div>
                                  </RadioGroup>
                                </div>
                              )}
                            </profileForm.Field>
                          </div>
                        </div>
                      </CardContent>

                      <CardFooter className="border-t justify-end px-6 pb-6">
                        <Button
                          type="submit"
                          disabled={isSubmitting}
                          className="w-full sm:w-auto"
                        >
                          {isSubmitting ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            m.settings_update_profile()
                          )}
                        </Button>
                      </CardFooter>
                    </>
                  )}
                </profileForm.Subscribe>
              </form>
            </Card>
          </section>

          <section className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-8 w-1 bg-primary/20 rounded-full" />
              <h2 className="text-xl font-bold">
                {m.settings_change_username_title()}
              </h2>
            </div>
            <Card className="border border-border/60 shadow-xs">
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  event.stopPropagation();
                  void changeUsernameForm.handleSubmit();
                }}
              >
                <changeUsernameForm.Subscribe
                  selector={(state) => [state.isSubmitting]}
                >
                  {([isSubmitting]) => (
                    <>
                      <CardContent className="p-6">
                        <p className="text-muted-foreground mb-6 text-sm">
                          {m.settings_change_username_desc()}
                        </p>

                        <changeUsernameForm.Field name="username">
                          {(field) => (
                            <FormTextField
                              field={field}
                              label={m.settings_username_label()}
                              srOnlyLabel
                              placeholder={m.settings_username_placeholder()}
                              disabled={isSubmitting}
                              className="h-10"
                            />
                          )}
                        </changeUsernameForm.Field>
                      </CardContent>

                      <CardFooter className="border-t justify-end px-6 pb-6">
                        <Button
                          type="submit"
                          disabled={isSubmitting}
                          className="w-full sm:w-auto"
                        >
                          {isSubmitting ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            m.settings_update_username()
                          )}
                        </Button>
                      </CardFooter>
                    </>
                  )}
                </changeUsernameForm.Subscribe>
              </form>
            </Card>
          </section>

          <section className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-8 w-1 bg-primary/20 rounded-full" />
              <h2 className="text-xl font-bold">
                {m.settings_login_methods_title()}
              </h2>
            </div>

            <Card className="border border-border/60 shadow-xs">
              <CardContent className="p-0">
                <div className="p-6 pb-0">
                  <p className="text-muted-foreground mb-6 text-sm">
                    {m.settings_login_methods_desc()}
                  </p>
                </div>
                <div className="divide-y divide-border">
                  {/* Password Method */}
                  <div className="flex items-center justify-between p-6 bg-chart-1/10">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-xl bg-card/80 flex items-center justify-center shadow-xs text-primary">
                        <Key className="h-5 w-5" />
                      </div>
                      <div>
                        <h3 className="font-semibold">
                          {m.settings_password_method()}
                        </h3>
                        <p className="text-xs text-muted-foreground">
                          {hasPassword
                            ? m.settings_password_secure_set()
                            : m.settings_password_not_set()}
                        </p>
                      </div>
                    </div>
                    <Badge
                      variant="outline"
                      className={
                        hasPassword
                          ? 'text-chart-1 border-chart-1/30 bg-chart-1/10'
                          : ''
                      }
                    >
                      {hasPassword
                        ? m.settings_enabled()
                        : m.settings_not_set()}
                    </Badge>
                  </div>

                  {/* OAuth Methods */}
                  <div className="p-6 space-y-4">
                    <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
                      {m.settings_linked_oauth()}
                    </h3>

                    {(identities?.identities || []).filter(
                      (i) => i.provider !== 'password',
                    ).length === 0 ? (
                      <div className="text-center p-8 border-2 border-dashed rounded-xl text-muted-foreground bg-secondary/30">
                        {m.settings_no_oauth()}
                      </div>
                    ) : (
                      <div className="grid gap-3">
                        {(identities?.identities || [])
                          .filter((i) => i.provider !== 'password')
                          .map((i) => (
                            <div
                              key={i.id}
                              className="flex items-center justify-between p-4 rounded-xl border border-border/60 bg-card/80"
                            >
                              <div className="flex items-center gap-4">
                                <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center text-secondary-foreground">
                                  <ProviderIcon
                                    provider={i.provider}
                                    className="h-5 w-5"
                                  />
                                </div>
                                <div>
                                  <h3 className="font-semibold capitalize">
                                    {providerLabel(i.provider)}
                                  </h3>
                                  <p className="text-xs text-muted-foreground break-all">
                                    {i.provider_user_id}
                                  </p>
                                </div>
                              </div>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive hover:bg-destructive/10"
                                onClick={() => handleUnlinkIdentity(i.id)}
                                title={m.settings_unlink()}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          ))}
                      </div>
                    )}

                    {/* Link Buttons Row */}
                    {linkableProviders.length > 0 ? (
                      <div className="flex flex-wrap gap-3 pt-2">
                        {linkableProviders.map((p) => (
                          <Button
                            key={p}
                            variant="outline"
                            onClick={() => handleOAuthLink(p)}
                            className="gap-2"
                          >
                            <ProviderIcon provider={p} className="h-4 w-4" />
                            {LINK_PROVIDER_LABELS[p]()}
                          </Button>
                        ))}
                      </div>
                    ) : (
                      enabledProviders.length === 0 && (
                        <p className="text-sm text-muted-foreground italic pt-2">
                          {m.settings_no_providers()}
                        </p>
                      )
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>

          <section className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-8 w-1 bg-primary/20 rounded-full" />
              <h2 className="text-xl font-bold">
                {hasPassword
                  ? m.settings_change_password()
                  : m.settings_set_password()}
              </h2>
            </div>
            <Card className="border border-border/60 shadow-xs">
              <CardContent className="p-6">
                {hasPassword ? (
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                      void changePasswordForm.handleSubmit();
                    }}
                    className="gap-4"
                  >
                    <changePasswordForm.Subscribe
                      selector={(state) => [state.isSubmitting]}
                    >
                      {([isSubmitting]) => (
                        <div className="grid md:grid-cols-2 gap-4">
                          <changePasswordForm.Field name="currentPassword">
                            {(field) => (
                              <FormTextField
                                field={field}
                                label={m.settings_current_password()}
                                type="password"
                                placeholder="••••••••"
                                disabled={isSubmitting}
                              />
                            )}
                          </changePasswordForm.Field>
                          <changePasswordForm.Field name="newPassword">
                            {(field) => (
                              <FormTextField
                                field={field}
                                label={m.settings_new_password()}
                                type="password"
                                placeholder="••••••••"
                                disabled={isSubmitting}
                              />
                            )}
                          </changePasswordForm.Field>
                          <changePasswordForm.Field name="confirmPassword">
                            {(field) => (
                              <FormTextField
                                field={field}
                                label={m.settings_confirm_password()}
                                type="password"
                                placeholder="••••••••"
                                disabled={isSubmitting}
                              />
                            )}
                          </changePasswordForm.Field>
                          <div className="flex items-end justify-end">
                            <Button
                              type="submit"
                              disabled={isSubmitting}
                              className="w-full md:w-auto"
                            >
                              {isSubmitting ? (
                                <>
                                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                  {m.settings_changing_password()}
                                </>
                              ) : (
                                m.settings_change_password()
                              )}
                            </Button>
                          </div>
                        </div>
                      )}
                    </changePasswordForm.Subscribe>
                  </form>
                ) : (
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                      void setPasswordForm.handleSubmit();
                    }}
                    className="space-y-4 max-w-md"
                  >
                    <setPasswordForm.Subscribe
                      selector={(state) => [state.isSubmitting]}
                    >
                      {([isSubmitting]) => (
                        <>
                          <Alert className="mb-4 bg-card/90 border-border/70">
                            <AlertDescription>
                              {m.settings_alert_set_password_info()}
                            </AlertDescription>
                          </Alert>
                          <setPasswordForm.Field name="newPassword">
                            {(field) => (
                              <FormTextField
                                field={field}
                                label={m.settings_new_password()}
                                type="password"
                                placeholder="••••••••"
                                disabled={isSubmitting}
                              />
                            )}
                          </setPasswordForm.Field>
                          <setPasswordForm.Field name="confirmPassword">
                            {(field) => (
                              <FormTextField
                                field={field}
                                label={m.settings_confirm_password_simple()}
                                type="password"
                                placeholder="••••••••"
                                disabled={isSubmitting}
                              />
                            )}
                          </setPasswordForm.Field>
                          <div className="flex justify-end pt-2">
                            <Button type="submit" disabled={isSubmitting}>
                              {isSubmitting ? (
                                <>
                                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                  {m.settings_setting_password()}
                                </>
                              ) : (
                                m.settings_set_password()
                              )}
                            </Button>
                          </div>
                        </>
                      )}
                    </setPasswordForm.Subscribe>
                  </form>
                )}
              </CardContent>
            </Card>
          </section>

          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-8 w-1 bg-primary/20 rounded-full" />
                <h2 className="text-xl font-bold">
                  {m.settings_passkeys_title()}
                </h2>
              </div>
              <Button onClick={() => setShowPasskeyModal(true)} size="sm">
                <Plus className="h-4 w-4 mr-2" />
                {m.settings_add_passkey()}
              </Button>
            </div>

            <Card className="border border-border/60 shadow-xs">
              <CardContent className="p-6">
                {passkeys.length === 0 ? (
                  <div className="text-center py-12 border-2 border-dashed border-border rounded-xl bg-secondary/30">
                    <div className="w-16 h-16 mx-auto bg-secondary/60 rounded-full flex items-center justify-center mb-4 text-muted-foreground">
                      <Key className="h-8 w-8" />
                    </div>
                    <p className="text-muted-foreground font-medium mb-1">
                      {m.settings_no_passkeys()}
                    </p>
                    <p className="text-sm text-muted-foreground/80">
                      {m.settings_add_passkey_promo()}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {passkeys.map((passkey) => (
                      <div
                        key={passkey.id}
                        className="flex items-center justify-between p-4 rounded-xl border border-border/60 bg-card/80"
                      >
                        <div className="flex items-center gap-4">
                          <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                            <Key className="h-5 w-5" />
                          </div>
                          <div>
                            <h3 className="font-semibold">{passkey.name}</h3>
                            <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                              <span>
                                {m.settings_created_at({
                                  date: new Date(
                                    passkey.created_at,
                                  ).toLocaleDateString(),
                                })}
                              </span>
                              {passkey.last_used_at && (
                                <span>
                                  {m.settings_last_used({
                                    date: new Date(
                                      passkey.last_used_at,
                                    ).toLocaleDateString(),
                                  })}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive hover:bg-destructive/10"
                          onClick={() =>
                            handleDeletePasskey(passkey.id, passkey.name)
                          }
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}

                <Alert className="mt-8 bg-card/90 border-border/70">
                  <Lightbulb className="h-4 w-4 text-chart-2" />
                  <AlertDescription className="text-muted-foreground">
                    <h3 className="font-semibold mb-1">
                      {m.settings_what_are_passkeys()}
                    </h3>
                    <p className="text-sm opacity-90">
                      {m.settings_passkeys_help_text()}
                    </p>
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </section>
        </div>

        <Dialog open={showPasskeyModal} onOpenChange={setShowPasskeyModal}>
          <DialogContent className="bg-card/95">
            <DialogHeader>
              <DialogTitle>{m.settings_add_new_passkey_title()}</DialogTitle>
              <DialogDescription>
                {m.settings_add_new_passkey_desc()}
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handlePasskeyModalSubmit}>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="passkeyName">
                    {m.settings_passkey_name_label()}
                  </Label>
                  <Input
                    id="passkeyName"
                    type="text"
                    value={passkeyName}
                    onChange={(e) => setPasskeyName(e.target.value)}
                    placeholder={m.settings_passkey_name_placeholder()}
                  />
                </div>
                <div className="flex gap-3">
                  <Button
                    type="button"
                    variant="secondary"
                    className="flex-1"
                    onClick={() => {
                      setShowPasskeyModal(false);
                      setPasskeyName('');
                    }}
                  >
                    {m.settings_cancel()}
                  </Button>
                  <Button type="submit" className="flex-1">
                    {m.settings_continue()}
                  </Button>
                </div>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/settings')({ component: SettingsPage });
