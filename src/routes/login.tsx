import {
  browserSupportsWebAuthnAutofill,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  startAuthentication,
  startRegistration,
  WebAuthnError,
} from '@simplewebauthn/browser';
import { useForm } from '@tanstack/react-form';
import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { KeyRound, Loader2 } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { FormTextField } from '@/components/form-text-field';
import { MinecraftFlowAlert } from '@/components/minecraft/minecraft-flow-alert';
import { PasswordField } from '@/components/password-field';
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
import { getErrorMessage, getFieldErrorMessage } from '@/lib/errors';
import {
  completeOidcFlow,
  isOidcFlow,
  oidcSearchSchema,
  redirectAfterAuth,
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
  const [oidcError, setOidcError] = useState(false);
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

      if (isOidcFlow(searchParams)) {
        // Already authenticated via cookie: complete the authorization directly.
        try {
          if (await completeOidcFlow(searchParams)) return;
        } catch (error) {
          console.log('OIDC auto-complete failed, showing login form', error);
          setOidcError(true);
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
      const credential = await startRegistration({
        optionsJSON: optionsJSON.creation_options.publicKey,
        useAutoRegister: true,
      });
      await apiClient('/api/v1/passkey/register/finish', {
        method: 'POST',
        body: { credential, name: 'Auto-registered Passkey' },
      });
      toast.success(m.login_passkey_registered(), {
        description: m.login_passkey_registered_desc(),
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
      const result = await apiClient<{ authorizationUrl?: string }>(
        '/api/v1/oauth/start',
        {
          method: 'POST',
          requiresAuth: false,
          body: { provider },
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
    minecraft: config?.minecraft_oauth,
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

  const showOAuthFirst = oauthProviderCount > 0;
  const showPasswordForm = config?.database_auth;

  return (
    <div className="min-h-full flex flex-col bg-background">
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <Card className="shadow-sm">
            <CardHeader className="text-center pb-4">
              <div className="flex justify-center mb-4">
                <BeaconIcon className="w-16 h-16" />
              </div>
              <CardTitle className="text-2xl font-semibold">
                {m.login_welcome_title()}
              </CardTitle>
              <CardDescription>
                {m.login_welcome_desc({ app_name: m.app_name() })}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
              {isOidcFlow(searchParams) && (
                <MinecraftFlowAlert title={m.login_minecraft_title()} />
              )}

              {oidcError && (
                <Alert variant="destructive">
                  <AlertDescription>
                    <p className="font-medium">{m.login_oidc_failed_title()}</p>
                    <p className="text-sm mt-1">{m.login_oidc_failed_desc()}</p>
                  </AlertDescription>
                </Alert>
              )}

              {/* OAuth first, when available */}
              {showOAuthFirst && (
                <div className="space-y-3">
                  <div className={`grid gap-3 ${oauthGridClass}`}>
                    {enabledOAuthProviders.map((provider) => (
                      <Button
                        key={provider}
                        type="button"
                        variant="outline"
                        onClick={() => handleOAuthLogin(provider)}
                        className="bg-card/80 hover:bg-card text-foreground border-border/70"
                      >
                        <ProviderIcon
                          provider={provider}
                          className="w-4 h-4 mr-2"
                        />
                        {providerLabel(provider)}
                      </Button>
                    ))}
                  </div>
                  {showPasswordForm && (
                    <div className="relative">
                      <div className="absolute inset-0 flex items-center">
                        <Separator className="w-full" />
                      </div>
                      <div className="relative flex justify-center text-xs uppercase">
                        <span className="bg-card px-2 text-muted-foreground">
                          {m.login_or_continue()}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Passkey button (always visible, secondary hierarchy) */}
              <div>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={handlePasskeyLogin}
                  disabled={passkeyLoading}
                  className="w-full text-muted-foreground hover:text-foreground"
                >
                  <KeyRound className="mr-2 h-4 w-4" />
                  {passkeyLoading
                    ? m.login_button_authenticating()
                    : m.login_passkey_btn()}
                </Button>
                {passkeyError && (
                  <Alert variant="destructive" className="mt-3">
                    <AlertDescription>{passkeyError}</AlertDescription>
                  </Alert>
                )}
              </div>

              {/* Password form */}
              {showPasswordForm && (
                <>
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                      void form.handleSubmit();
                    }}
                    method="post"
                    className="space-y-4"
                  >
                    <form.Subscribe selector={(state) => [state.isSubmitting]}>
                      {([isSubmitting]) => (
                        <>
                          <form.Field name="username">
                            {(field) => {
                              const isInvalid =
                                field.state.meta.isTouched &&
                                !field.state.meta.isValid;
                              return (
                                <div className="space-y-2">
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
                                  {isInvalid && (
                                    <p className="text-sm text-destructive">
                                      {getFieldErrorMessage(
                                        field.state.meta.errors,
                                      )}
                                    </p>
                                  )}
                                </div>
                              );
                            }}
                          </form.Field>
                          <form.Field name="password">
                            {(field) => (
                              <PasswordField
                                label={m.login_password_label()}
                                value={field.state.value}
                                onChange={field.handleChange}
                                placeholder={m.login_password_placeholder()}
                                disabled={isSubmitting}
                                autoComplete="current-password webauthn"
                                errorMessage={getFieldErrorMessage(
                                  field.state.meta.errors,
                                )}
                                isInvalid={
                                  field.state.meta.isTouched &&
                                  !field.state.meta.isValid
                                }
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
                            disabled={isSubmitting}
                            className="w-full"
                          >
                            {isSubmitting ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
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
                  <div className="text-center">
                    <p className="text-sm text-muted-foreground">
                      {m.login_no_account()}{' '}
                      <Link
                        to="/register"
                        search={{
                          client_id: searchParams.client_id,
                          redirect_uri: searchParams.redirect_uri,
                          scope: searchParams.scope,
                          state: searchParams.state,
                          code_challenge: searchParams.code_challenge,
                          code_challenge_method:
                            searchParams.code_challenge_method,
                          nonce: searchParams.nonce,
                        }}
                        className="text-primary hover:text-primary/80 font-medium transition-colors"
                      >
                        {m.login_create_one()}
                      </Link>
                    </p>
                  </div>
                </>
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
  validateSearch: oidcSearchSchema,
  head: () => ({
    meta: [{ title: m.login_welcome_title() }],
  }),
});
