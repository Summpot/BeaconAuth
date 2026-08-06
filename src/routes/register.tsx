import { useForm } from '@tanstack/react-form';
import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { Loader2 } from 'lucide-react';
import { useState } from 'react';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { FormTextField } from '@/components/form-text-field';
import { MinecraftFlowAlert } from '@/components/minecraft/minecraft-flow-alert';
import { PasswordField } from '@/components/password-field';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { getErrorMessage, getFieldErrorMessage } from '@/lib/errors';
import {
  isOidcFlow,
  oidcSearchSchema,
  redirectAfterAuth,
} from '@/lib/minecraft-flow';
import * as m from '@/paraglide/messages';
import { apiClient, queryKeys } from '../utils/api';

const makeRegisterFormSchema = () =>
  z
    .object({
      username: z
        .string()
        .trim()
        .min(3, m.settings_validation_username_min_length({ min: 3 }))
        .max(16, m.settings_validation_username_max_length({ max: 16 }))
        .regex(
          /^[A-Za-z0-9_]+$/,
          m.settings_validation_username_invalid_chars(),
        ),
      password: z
        .string()
        .min(6, m.settings_validation_password_min_length({ min: 6 })),
      confirmPassword: z
        .string()
        .min(1, m.settings_validation_confirm_password_required()),
    })
    .refine((data) => data.password === data.confirmPassword, {
      message: m.settings_validation_passwords_dont_match(),
      path: ['confirmPassword'],
    });

function RegisterPage() {
  const searchParams = Route.useSearch();
  const queryClient = useQueryClient();
  const [formError, setFormError] = useState<string>('');

  const registerFormSchema = makeRegisterFormSchema();
  const form = useForm({
    defaultValues: {
      username: '',
      password: '',
      confirmPassword: '',
    },
    validators: {
      onChange: registerFormSchema,
      onSubmit: registerFormSchema,
    },
    onSubmit: async ({ value }) => {
      setFormError('');
      try {
        await apiClient('/api/v1/register', {
          method: 'POST',
          requiresAuth: false,
          body: { username: value.username, password: value.password },
        });
      } catch (error) {
        setFormError(
          getErrorMessage(error, m.register_error_registration_failed()),
        );
        return;
      }

      // Ensure any stale /me cache (especially a cached 401 from earlier) is cleared
      // before we hit /profile.
      await queryClient.invalidateQueries({ queryKey: queryKeys.userMe() });

      try {
        await redirectAfterAuth(searchParams);
      } catch (error) {
        setFormError(
          getErrorMessage(error, m.register_error_complete_failed()),
        );
      }
    },
  });

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
                {m.button_create_account()}
              </CardTitle>
              <CardDescription>
                {m.register_description_join_community()}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
              {isOidcFlow(searchParams) && (
                <MinecraftFlowAlert title={m.register_minecraft_title()} />
              )}

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
                                autoComplete="username"
                                autoCapitalize="none"
                                autoCorrect="off"
                                spellCheck={false}
                                placeholder={m.register_username_placeholder()}
                                disabled={isSubmitting}
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
                            autoComplete="new-password"
                            minLength={6}
                            placeholder={m.settings_create_password_placeholder()}
                            disabled={isSubmitting}
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

                      <form.Field name="confirmPassword">
                        {(field) => (
                          <PasswordField
                            label={m.settings_confirm_password_simple()}
                            value={field.state.value}
                            onChange={field.handleChange}
                            autoComplete="new-password"
                            minLength={6}
                            placeholder={m.settings_confirm_password_simple_placeholder()}
                            disabled={isSubmitting}
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
                            {m.register_button_creating_account()}
                          </>
                        ) : (
                          m.button_create_account()
                        )}
                      </Button>
                    </>
                  )}
                </form.Subscribe>
              </form>

              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  {m.register_already_have_account()}{' '}
                  <Link
                    to="/login"
                    search={{
                      client_id: searchParams.client_id,
                      redirect_uri: searchParams.redirect_uri,
                      scope: searchParams.scope,
                      state: searchParams.state,
                      code_challenge: searchParams.code_challenge,
                      code_challenge_method: searchParams.code_challenge_method,
                      nonce: searchParams.nonce,
                    }}
                    className="text-primary hover:text-primary/80 font-medium transition-colors"
                  >
                    {m.login_button_signin()}
                  </Link>
                </p>
              </div>
            </CardContent>
          </Card>

          <div className="mt-6 text-center">
            <p className="text-xs text-muted-foreground">
              {m.register_password_stored_securely()}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/register')({
  component: RegisterPage,
  validateSearch: oidcSearchSchema,
  head: () => ({
    meta: [{ title: m.button_create_account() }],
  }),
});
