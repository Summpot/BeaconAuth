import {
  browserSupportsWebAuthnAutofill,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  startAuthentication,
  WebAuthnError,
} from '@simplewebauthn/browser';
import { useForm } from '@tanstack/react-form';
import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { KeyRound, Loader2 } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { FormTextField } from '@/components/form-text-field';
import { MinecraftFlowAlert } from '@/components/minecraft/minecraft-flow-alert';
import {
  OAUTH_PROVIDERS,
  type OAuthProvider,
  ProviderIcon,
  providerLabel,
} from '@/components/provider-icon';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { PageLoader } from '@/components/ui/page-loader';
import { Separator } from '@/components/ui/separator';
import { getErrorMessage } from '@/lib/errors';
import {
  isMinecraftFlow,
  type MinecraftSearchParams,
  minecraftSearchSchema,
  redirectAfterAuth,
  tryCompleteMinecraftFlow,
} from '@/lib/minecraft-flow';
import * as m from '@/paraglide/messages';
import { apiClient, queryKeys, type ServerConfig } from '../utils/api';

const makeLoginFormSchema = () =>
  z.object({
    username: z.string().min(1, m.login_validation_username_required()),
    password: z.string().min(1, m.login_validation_password_required()),
  });

function LoginPage() {
  const searchParams = Route.useSearch();
  const queryClient = useQueryClient();
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [passkeyError, setPasskeyError] = useState<string>('');
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [formError, setFormError] = useState<string>('');
  const conditionalUIStarted = useRef(false);

  const loginFormSchema = makeLoginFormSchema();
  const form = useForm({
    defaultValues: {
      username: '',
      password: '',
    },
    validators: {
      onChange: loginFormSchema,
      onSubmit: loginFormSchema,
    },
    onSubmit: async ({ value }) => {
      setFormError('');
      try {
        await apiClient('/api/v1/login', {
          method: 'POST',
          requiresAuth: false,
          body: { username: value.username, password: value.password },
        });

        await queryClient.invalidateQueries({ queryKey: queryKeys.userMe() });
        tryAutoRegisterPasskey().catch(() => {});

        await redirectAfterAuth(searchParams);
      } catch (error) {
        setFormError(
          getErrorMessage(error, m.login_error_failed_connect_server()),
        );
      }
    },
  });

  useEffect(() => {
    const initialize = async () => {
      try {
        const configData = await apiClient<ServerConfig>('/api/v1/config', {
          requiresAuth: false,
        });
        setConfig(configData);
      } catch (error) {
        console.error('Failed to load server config:', error);
      }

      if (isMinecraftFlow(searchParams)) {
        try {
          if (await tryCompleteMinecraftFlow(searchParams)) return;
        } catch (error) {
          console.log('Auto-login failed, showing login form', error);
        }
      }
      setConfigLoading(false);
    };
    initialize();
  }, [searchParams]);

  const completePasskeyAuth = useCallback(
    async (credential: unknown) => {
      await apiClient('/api/v1/passkey/auth/finish', {
        method: 'POST',
        requiresAuth: false,
        body: { credential },
      });

      await queryClient.invalidateQueries({ queryKey: queryKeys.userMe() });

      await redirectAfterAuth(searchParams);
    },
    [queryClient, searchParams],
  );

  useEffect(() => {
    const initConditionalUI = async () => {
      if (conditionalUIStarted.current) return;
      if (!browserSupportsWebAuthnAutofill()) return;

      try {
        conditionalUIStarted.current = true;
        const optionsJSON = await apiClient<{
          request_options: { publicKey: PublicKeyCredentialRequestOptionsJSON };
        }>('/api/v1/passkey/auth/start', {
          method: 'POST',
          requiresAuth: false,
          body: {},
        });
        const credential = await startAuthentication({
          optionsJSON: optionsJSON.request_options.publicKey,
          useBrowserAutofill: true,
        });
        await completePasskeyAuth(credential);
      } catch (err) {
        if (
          err instanceof WebAuthnError &&
          err.code === 'ERROR_CEREMONY_ABORTED'
        )
          return;
        console.error('Conditional UI error:', err);
      }
    };
    if (!configLoading) initConditionalUI();
  }, [configLoading, completePasskeyAuth]);

  const tryAutoRegisterPasskey = async () => {
    try {
      const optionsJSON = await apiClient<{
        creation_options: { publicKey: PublicKeyCredentialCreationOptionsJSON };
      }>('/api/v1/passkey/register/start', {
        method: 'POST',
        body: { name: 'Auto-registered Passkey' },
      });
      const { startRegistration } = await import('@simplewebauthn/browser');
      const credential = await startRegistration({
        optionsJSON: optionsJSON.creation_options.publicKey,
        useAutoRegister: true,
      });
      await apiClient('/api/v1/passkey/register/finish', {
        method: 'POST',
        body: { credential, name: 'Auto-registered Passkey' },
      });
    } catch (err) {
      console.log('Auto-register passkey failed (expected):', err);
    }
  };

  const handlePasskeyLogin = async () => {
    setPasskeyError('');
    setPasskeyLoading(true);
    try {
      const optionsJSON = await apiClient<{
        request_options: { publicKey: PublicKeyCredentialRequestOptionsJSON };
      }>('/api/v1/passkey/auth/start', {
        method: 'POST',
        requiresAuth: false,
        body: {},
      });
      const credential = await startAuthentication({
        optionsJSON: optionsJSON.request_options.publicKey,
      });
      await completePasskeyAuth(credential);
    } catch (err) {
      if (err instanceof WebAuthnError) {
        setPasskeyError(
          err.code === 'ERROR_CEREMONY_ABORTED'
            ? m.login_passkey_cancelled()
            : m.login_passkey_error({ message: err.message }),
        );
      } else if (err instanceof Error) {
        setPasskeyError(err.message);
      } else {
        setPasskeyError(m.login_passkey_unknown_error());
      }
    } finally {
      setPasskeyLoading(false);
    }
  };

  const handleOAuthLogin = async (provider: OAuthProvider) => {
    try {
      if (isMinecraftFlow(searchParams)) {
        sessionStorage.setItem('minecraft_challenge', searchParams.challenge);
        sessionStorage.setItem(
          'minecraft_redirect_port',
          searchParams.redirect_port.toString(),
        );
      } else {
        sessionStorage.removeItem('minecraft_challenge');
        sessionStorage.removeItem('minecraft_redirect_port');
      }
      const result = await apiClient<{ authorizationUrl?: string }>(
        '/api/v1/oauth/start',
        {
          method: 'POST',
          requiresAuth: false,
          body: {
            provider,
            challenge: searchParams.challenge || '',
            redirect_port: searchParams.redirect_port || 0,
          },
        },
      );
      if (result.authorizationUrl)
        window.location.href = result.authorizationUrl;
    } catch (error) {
      console.error(`${provider} login failed:`, error);
    }
  };

  const oauthEnabled: Record<OAuthProvider, boolean | undefined> = {
    github: config?.github_oauth,
    google: config?.google_oauth,
    microsoft: config?.microsoft_oauth,
  };
  const enabledOAuthProviders = OAUTH_PROVIDERS.filter(
    (provider) => oauthEnabled[provider],
  );
  const oauthProviderCount = enabledOAuthProviders.length;

  const oauthGridClass =
    oauthProviderCount <= 1
      ? 'grid-cols-1'
      : oauthProviderCount === 2
        ? 'grid-cols-1 sm:grid-cols-2'
        : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3';

  if (configLoading) {
    return (
      <PageLoader
        title={m.profile_loading()}
        icon={<BeaconIcon className="size-6 text-primary" />}
      />
    );
  }

  return (
    <div className="flex min-h-full flex-col bg-surface">
      <div className="flex flex-1 items-center justify-center p-6">
        <div className="w-full max-w-md">
          <Card className="rounded-xl">
            <CardHeader className="pb-2 text-center">
              <div className="mb-4 flex justify-center">
                <div className="flex size-20 items-center justify-center rounded-full bg-primary-container">
                  <BeaconIcon className="size-12" />
                </div>
              </div>
              <CardTitle className="text-headline-sm">
                {m.login_welcome_title()}
              </CardTitle>
              <CardDescription className="text-body-lg">
                {m.login_welcome_desc({ app_name: m.app_name() })}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
              {isMinecraftFlow(searchParams) && (
                <MinecraftFlowAlert title={m.login_minecraft_title()} />
              )}

              {config?.database_auth && (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    void form.handleSubmit();
                  }}
                  method="post"
                  className="space-y-5"
                >
                  <form.Subscribe selector={(state) => [state.isSubmitting]}>
                    {([isSubmitting]) => (
                      <>
                        <form.Field name="username">
                          {(field) => (
                            <FormTextField
                              field={field}
                              label={m.login_username_label()}
                              type="text"
                              placeholder={m.login_username_placeholder()}
                              disabled={isSubmitting}
                              autoComplete="username webauthn"
                              autoCapitalize="none"
                              autoCorrect="off"
                              spellCheck={false}
                            />
                          )}
                        </form.Field>
                        <form.Field name="password">
                          {(field) => (
                            <FormTextField
                              field={field}
                              label={m.login_password_label()}
                              type="password"
                              placeholder={m.login_password_placeholder()}
                              disabled={isSubmitting}
                              autoComplete="current-password webauthn"
                            />
                          )}
                        </form.Field>
                        {formError && (
                          <Alert variant="destructive">
                            <AlertDescription>{formError}</AlertDescription>
                          </Alert>
                        )}
                        <Button
                          type="submit"
                          size="lg"
                          disabled={isSubmitting}
                          className="w-full"
                        >
                          {isSubmitting ? (
                            <>
                              <Loader2 className="animate-spin" />
                              {m.login_button_authenticating()}
                            </>
                          ) : (
                            m.login_button_signin()
                          )}
                        </Button>
                      </>
                    )}
                  </form.Subscribe>
                </form>
              )}

              <div>
                {config?.database_auth && (
                  <div className="relative my-6">
                    <div className="absolute inset-0 flex items-center">
                      <Separator className="w-full" />
                    </div>
                    <div className="relative flex justify-center">
                      <span className="bg-surface-container-low px-3 text-label-md text-on-surface-variant uppercase">
                        {m.login_or_use()}
                      </span>
                    </div>
                  </div>
                )}
                <Button
                  type="button"
                  variant="tonal"
                  size="lg"
                  onClick={handlePasskeyLogin}
                  disabled={passkeyLoading}
                  className="w-full"
                >
                  <KeyRound />
                  {passkeyLoading
                    ? m.login_button_authenticating()
                    : m.login_passkey_btn()}
                </Button>
                {passkeyError && (
                  <Alert variant="destructive" className="mt-4">
                    <AlertDescription>{passkeyError}</AlertDescription>
                  </Alert>
                )}
              </div>

              {oauthProviderCount > 0 && (
                <div className="space-y-4">
                  <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                      <Separator className="w-full" />
                    </div>
                    <div className="relative flex justify-center">
                      <span className="bg-surface-container-low px-3 text-label-md text-on-surface-variant uppercase">
                        {m.login_or_continue()}
                      </span>
                    </div>
                  </div>
                  <div className={`grid gap-3 ${oauthGridClass}`}>
                    {enabledOAuthProviders.map((provider) => (
                      <Button
                        key={provider}
                        type="button"
                        variant="outlined"
                        onClick={() => handleOAuthLogin(provider)}
                        className="text-on-surface"
                      >
                        <ProviderIcon provider={provider} className="size-5" />
                        {providerLabel(provider)}
                      </Button>
                    ))}
                  </div>
                </div>
              )}

              {config?.database_auth && (
                <div className="text-center">
                  <p className="text-body-md text-on-surface-variant">
                    {m.login_no_account()}{' '}
                    <Link
                      to="/register"
                      search={{
                        challenge: searchParams.challenge,
                        redirect_port: searchParams.redirect_port,
                      }}
                      className="rounded-xs text-label-lg text-primary transition-colors duration-200 ease-standard hover:underline"
                    >
                      {m.login_create_one()}
                    </Link>
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/login')({
  component: LoginPage,
  validateSearch: (search: Record<string, unknown>): MinecraftSearchParams =>
    minecraftSearchSchema.parse(search),
});
