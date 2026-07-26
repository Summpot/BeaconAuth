import { useForm } from '@tanstack/react-form';
import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { Loader2 } from 'lucide-react';
import { useState } from 'react';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { FormTextField } from '@/components/form-text-field';
import { MinecraftFlowAlert } from '@/components/minecraft/minecraft-flow-alert';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { getErrorMessage } from '@/lib/errors';
import {
  isMinecraftFlow,
  minecraftSearchSchema,
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
                {m.button_create_account()}
              </CardTitle>
              <CardDescription className="text-body-lg">
                {m.register_description_join_community()}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
              {isMinecraftFlow(searchParams) && (
                <MinecraftFlowAlert title={m.register_minecraft_title()} />
              )}

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
                            autoComplete="username"
                            autoCapitalize="none"
                            autoCorrect="off"
                            spellCheck={false}
                            placeholder={m.register_username_placeholder()}
                            disabled={isSubmitting}
                          />
                        )}
                      </form.Field>

                      <form.Field name="password">
                        {(field) => (
                          <FormTextField
                            field={field}
                            label={m.login_password_label()}
                            type="password"
                            autoComplete="new-password"
                            minLength={6}
                            placeholder={m.settings_create_password_placeholder()}
                            disabled={isSubmitting}
                          />
                        )}
                      </form.Field>

                      <form.Field name="confirmPassword">
                        {(field) => (
                          <FormTextField
                            field={field}
                            label={m.settings_confirm_password_simple()}
                            type="password"
                            autoComplete="new-password"
                            minLength={6}
                            placeholder={m.settings_confirm_password_simple_placeholder()}
                            disabled={isSubmitting}
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
                <p className="text-body-md text-on-surface-variant">
                  {m.register_already_have_account()}{' '}
                  <Link
                    to="/login"
                    search={{
                      challenge: searchParams.challenge,
                      redirect_port: searchParams.redirect_port,
                    }}
                    className="rounded-xs text-label-lg text-primary transition-colors duration-200 ease-standard hover:underline"
                  >
                    {m.login_button_signin()}
                  </Link>
                </p>
              </div>
            </CardContent>
          </Card>

          <div className="mt-6 text-center">
            <p className="text-body-sm text-on-surface-variant">
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
  validateSearch: (search: Record<string, unknown>) =>
    minecraftSearchSchema.parse(search),
});
