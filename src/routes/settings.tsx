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
import { Label } from '@/components/ui/label';
import { PageLoader } from '@/components/ui/page-loader';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { TextField } from '@/components/ui/text-field';
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
      <div className="flex min-h-full items-center justify-center bg-surface p-4">
        <div className="w-full max-w-md">
          <Card className="rounded-xl text-center">
            <CardContent className="py-10">
              <div className="mb-6 inline-flex size-20 items-center justify-center rounded-full bg-surface-container-high">
                <BeaconIcon className="size-12" />
              </div>
              <CardTitle className="mb-3 text-headline-sm">
                {m.settings_not_authenticated()}
              </CardTitle>
              <CardDescription className="mb-8 text-body-lg">
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
    <div className="min-h-full bg-surface pb-20">
      <div className="mx-auto max-w-5xl px-4 pt-12 md:px-6">
        <div className="mb-10">
          <h1 className="mb-2 text-headline-lg text-on-surface">
            {m.settings_title()}
          </h1>
          <p className="text-body-lg text-on-surface-variant">
            {m.settings_subtitle({ username: user.username })}
          </p>
        </div>

        {message && (
          <Alert
            variant={message.type === 'success' ? 'success' : 'destructive'}
            className="mb-8"
          >
            {message.type === 'success' ? <CheckCircle2 /> : <XCircle />}
            <AlertDescription className="w-full">
              <div className="flex w-full items-center justify-between gap-4">
                <p className="text-title-sm">{message.text}</p>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="-my-1 shrink-0 text-current"
                  aria-label={m.common_close()}
                  onClick={() => setMessage(null)}
                >
                  <X />
                </Button>
              </div>
            </AlertDescription>
          </Alert>
        )}

        <div className="grid gap-10">
          <section className="space-y-3">
            <h2 className="px-1 text-title-md text-primary">
              {m.settings_profile_title()}
            </h2>

            <Card>
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
                      <CardContent className="space-y-6 p-6">
                        <p className="text-body-md text-on-surface-variant">
                          {m.settings_profile_desc()}
                        </p>

                        <div className="flex flex-col items-start gap-6 sm:flex-row">
                          <div className="flex items-center gap-4">
                            <Avatar className="size-16">
                              {user.avatar_url ? (
                                <AvatarImage
                                  src={user.avatar_url}
                                  alt={user.username}
                                />
                              ) : null}
                              <AvatarFallback className="text-headline-sm">
                                {user.username.charAt(0).toUpperCase()}
                              </AvatarFallback>
                            </Avatar>
                            <div>
                              <div className="text-title-md text-on-surface">
                                {user.username}
                              </div>
                              <div className="font-mono text-body-sm text-on-surface-variant">
                                {user.id}
                              </div>
                            </div>
                          </div>

                          <div className="flex-1 space-y-6">
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
                                          aria-label={m.aria_email_info()}
                                        >
                                          <Lightbulb />
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
                                <div className="space-y-2">
                                  <Label className="px-1">
                                    {m.settings_avatar_source_label()}
                                  </Label>
                                  <RadioGroup
                                    value={field.state.value}
                                    onValueChange={(value) =>
                                      field.handleChange(
                                        value as ProfileData['avatar_source'],
                                      )
                                    }
                                    className="grid gap-0 overflow-hidden rounded-md bg-surface-container"
                                  >
                                    <div className="flex min-h-14 items-center justify-between gap-4 px-4 py-3">
                                      <div className="flex items-center gap-4">
                                        <RadioGroupItem
                                          value=""
                                          id="avatar_auto"
                                        />
                                        <Label
                                          htmlFor="avatar_auto"
                                          className="cursor-pointer text-body-lg text-on-surface"
                                        >
                                          {m.settings_avatar_source_auto()}
                                        </Label>
                                      </div>
                                    </div>

                                    {enabledProviders.map((p) => (
                                      <div
                                        key={p}
                                        className="flex min-h-14 items-center justify-between gap-4 border-t border-outline-variant px-4 py-3"
                                      >
                                        <div className="flex items-center gap-4">
                                          <RadioGroupItem
                                            value={p}
                                            id={`avatar_${p}`}
                                            disabled={!linkedProviders.has(p)}
                                          />
                                          <Label
                                            htmlFor={`avatar_${p}`}
                                            className="flex cursor-pointer items-center gap-2 text-body-lg text-on-surface"
                                          >
                                            <ProviderIcon
                                              provider={p}
                                              className="size-5"
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

                                    <div className="flex min-h-14 items-center justify-between gap-4 border-t border-outline-variant px-4 py-3">
                                      <div className="flex items-center gap-4">
                                        <RadioGroupItem
                                          value="gravatar"
                                          id="avatar_gravatar"
                                          disabled={email.trim().length === 0}
                                        />
                                        <Label
                                          htmlFor="avatar_gravatar"
                                          className="cursor-pointer text-body-lg text-on-surface"
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

                      <CardFooter className="justify-end px-6 pb-6">
                        <Button
                          type="submit"
                          disabled={isSubmitting}
                          className="w-full sm:w-auto"
                        >
                          {isSubmitting ? (
                            <Loader2 className="animate-spin" />
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

          <section className="space-y-3">
            <h2 className="px-1 text-title-md text-primary">
              {m.settings_change_username_title()}
            </h2>
            <Card>
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
                        <p className="mb-6 text-body-md text-on-surface-variant">
                          {m.settings_change_username_desc()}
                        </p>

                        <changeUsernameForm.Field name="username">
                          {(field) => (
                            <FormTextField
                              field={field}
                              label={m.settings_username_label()}
                              placeholder={m.settings_username_placeholder()}
                              disabled={isSubmitting}
                            />
                          )}
                        </changeUsernameForm.Field>
                      </CardContent>

                      <CardFooter className="justify-end px-6 pb-6">
                        <Button
                          type="submit"
                          disabled={isSubmitting}
                          className="w-full sm:w-auto"
                        >
                          {isSubmitting ? (
                            <Loader2 className="animate-spin" />
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

          <section className="space-y-3">
            <h2 className="px-1 text-title-md text-primary">
              {m.settings_login_methods_title()}
            </h2>

            <Card>
              <CardContent className="p-0">
                <div className="px-6 pt-6">
                  <p className="mb-6 text-body-md text-on-surface-variant">
                    {m.settings_login_methods_desc()}
                  </p>
                </div>

                {/* Password method */}
                <div className="flex items-center justify-between gap-4 px-6 py-4">
                  <div className="flex items-center gap-4">
                    <div className="flex size-10 items-center justify-center rounded-full bg-primary-container text-on-primary-container">
                      <Key className="size-5" />
                    </div>
                    <div>
                      <h3 className="text-title-md text-on-surface">
                        {m.settings_password_method()}
                      </h3>
                      <p className="text-body-sm text-on-surface-variant">
                        {hasPassword
                          ? m.settings_password_secure_set()
                          : m.settings_password_not_set()}
                      </p>
                    </div>
                  </div>
                  <Badge variant={hasPassword ? 'primary' : 'outline'}>
                    {hasPassword ? m.settings_enabled() : m.settings_not_set()}
                  </Badge>
                </div>

                {/* Linked OAuth identities */}
                <div className="space-y-4 border-t border-outline-variant p-6">
                  <h3 className="text-title-sm text-on-surface-variant uppercase">
                    {m.settings_linked_oauth()}
                  </h3>

                  {(identities?.identities || []).filter(
                    (i) => i.provider !== 'password',
                  ).length === 0 ? (
                    <div className="rounded-md border border-outline-variant p-8 text-center text-body-md text-on-surface-variant">
                      {m.settings_no_oauth()}
                    </div>
                  ) : (
                    <div className="overflow-hidden rounded-md bg-surface-container">
                      {(identities?.identities || [])
                        .filter((i) => i.provider !== 'password')
                        .map((i, index) => (
                          <div
                            key={i.id}
                            className={`flex items-center justify-between gap-4 p-4 ${
                              index > 0 ? 'border-t border-outline-variant' : ''
                            }`}
                          >
                            <div className="flex min-w-0 items-center gap-4">
                              <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-secondary-container text-on-secondary-container">
                                <ProviderIcon
                                  provider={i.provider}
                                  className="size-5"
                                />
                              </div>
                              <div className="min-w-0">
                                <h3 className="text-title-md text-on-surface capitalize">
                                  {providerLabel(i.provider)}
                                </h3>
                                <p className="break-all text-body-sm text-on-surface-variant">
                                  {i.provider_user_id}
                                </p>
                              </div>
                            </div>
                            <Button
                              variant="destructive-text"
                              size="icon"
                              onClick={() => handleUnlinkIdentity(i.id)}
                              title={m.settings_unlink()}
                              aria-label={m.settings_unlink()}
                            >
                              <Trash2 />
                            </Button>
                          </div>
                        ))}
                    </div>
                  )}

                  {linkableProviders.length > 0 ? (
                    <div className="flex flex-wrap gap-3 pt-2">
                      {linkableProviders.map((p) => (
                        <Button
                          key={p}
                          variant="outlined"
                          onClick={() => handleOAuthLink(p)}
                          className="text-on-surface"
                        >
                          <ProviderIcon provider={p} className="size-5" />
                          {LINK_PROVIDER_LABELS[p]()}
                        </Button>
                      ))}
                    </div>
                  ) : (
                    enabledProviders.length === 0 && (
                      <p className="pt-2 text-body-md text-on-surface-variant">
                        {m.settings_no_providers()}
                      </p>
                    )
                  )}
                </div>
              </CardContent>
            </Card>
          </section>

          <section className="space-y-3">
            <h2 className="px-1 text-title-md text-primary">
              {hasPassword
                ? m.settings_change_password()
                : m.settings_set_password()}
            </h2>
            <Card>
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
                        <div className="grid gap-6 md:grid-cols-2">
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
                                  <Loader2 className="animate-spin" />
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
                    className="max-w-md space-y-6"
                  >
                    <setPasswordForm.Subscribe
                      selector={(state) => [state.isSubmitting]}
                    >
                      {([isSubmitting]) => (
                        <>
                          <Alert variant="info">
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
                                  <Loader2 className="animate-spin" />
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

          <section className="space-y-3">
            <div className="flex items-center justify-between gap-4">
              <h2 className="px-1 text-title-md text-primary">
                {m.settings_passkeys_title()}
              </h2>
              <Button onClick={() => setShowPasskeyModal(true)} variant="tonal">
                <Plus />
                {m.settings_add_passkey()}
              </Button>
            </div>

            <Card>
              <CardContent className="p-6">
                {passkeys.length === 0 ? (
                  <div className="rounded-md border border-outline-variant py-12 text-center">
                    <div className="mx-auto mb-4 flex size-16 items-center justify-center rounded-full bg-surface-container-high text-on-surface-variant">
                      <Key className="size-8" />
                    </div>
                    <p className="mb-1 text-title-md text-on-surface">
                      {m.settings_no_passkeys()}
                    </p>
                    <p className="text-body-md text-on-surface-variant">
                      {m.settings_add_passkey_promo()}
                    </p>
                  </div>
                ) : (
                  <div className="overflow-hidden rounded-md bg-surface-container">
                    {passkeys.map((passkey, index) => (
                      <div
                        key={passkey.id}
                        className={`flex items-center justify-between gap-4 p-4 ${
                          index > 0 ? 'border-t border-outline-variant' : ''
                        }`}
                      >
                        <div className="flex min-w-0 items-center gap-4">
                          <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-primary-container text-on-primary-container">
                            <Key className="size-5" />
                          </div>
                          <div className="min-w-0">
                            <h3 className="truncate text-title-md text-on-surface">
                              {passkey.name}
                            </h3>
                            <div className="mt-0.5 flex flex-wrap items-center gap-x-4 text-body-sm text-on-surface-variant">
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
                          variant="destructive-text"
                          size="icon"
                          title={m.settings_delete_passkey()}
                          aria-label={m.settings_delete_passkey()}
                          onClick={() =>
                            handleDeletePasskey(passkey.id, passkey.name)
                          }
                        >
                          <Trash2 />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}

                <Alert variant="warning" className="mt-8">
                  <Lightbulb />
                  <AlertDescription>
                    <h3 className="text-title-sm">
                      {m.settings_what_are_passkeys()}
                    </h3>
                    <p className="text-body-md opacity-90">
                      {m.settings_passkeys_help_text()}
                    </p>
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </section>
        </div>

        <Dialog open={showPasskeyModal} onOpenChange={setShowPasskeyModal}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{m.settings_add_new_passkey_title()}</DialogTitle>
              <DialogDescription>
                {m.settings_add_new_passkey_desc()}
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handlePasskeyModalSubmit}>
              <div className="space-y-6">
                <TextField
                  id="passkeyName"
                  type="text"
                  label={m.settings_passkey_name_label()}
                  value={passkeyName}
                  onChange={(e) => setPasskeyName(e.target.value)}
                  placeholder={m.settings_passkey_name_placeholder()}
                />
                <div className="flex justify-end gap-2">
                  <Button
                    type="button"
                    variant="text"
                    onClick={() => {
                      setShowPasskeyModal(false);
                      setPasskeyName('');
                    }}
                  >
                    {m.settings_cancel()}
                  </Button>
                  <Button type="submit">{m.settings_continue()}</Button>
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
