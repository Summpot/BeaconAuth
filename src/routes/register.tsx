import { zodResolver } from '@hookform/resolvers/zod';
import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { Loader2 } from 'lucide-react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
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
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import * as m from '@/paraglide/messages';
import { ApiError, apiClient, queryKeys } from '../utils/api';

const searchParamsSchema = z.object({
  challenge: z.string().min(1).optional(),
  redirect_port: z.coerce.number().min(1).max(65535).optional(),
});

type SearchParams = z.infer<typeof searchParamsSchema>;

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

type RegisterFormData = z.infer<ReturnType<typeof makeRegisterFormSchema>>;

function RegisterPage() {
  const searchParams = Route.useSearch();
  const queryClient = useQueryClient();

  const getErrorMessage = (error: unknown, fallback: string) => {
    if (error instanceof ApiError) {
      const data = error.data as { message?: string } | undefined;
      return data?.message ?? fallback;
    }
    return fallback;
  };

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<RegisterFormData>({
    resolver: zodResolver(makeRegisterFormSchema()),
  });

  const onSubmit = async (data: RegisterFormData) => {
    try {
      await apiClient('/api/v1/register', {
        method: 'POST',
        requiresAuth: false,
        body: { username: data.username, password: data.password },
      });
    } catch (error) {
      setError('root', {
        type: 'manual',
        message: getErrorMessage(error, m.register_error_registration_failed()),
      });
      return;
    }

    // Ensure any stale /me cache (especially a cached 401 from earlier) is cleared
    // before we hit /profile.
    await queryClient.invalidateQueries({ queryKey: queryKeys.userMe() });

    try {
      if (searchParams.challenge && searchParams.redirect_port) {
        const result = await apiClient<{ redirectUrl?: string }>(
          '/api/v1/minecraft-jwt',
          {
            method: 'POST',
            body: {
              challenge: searchParams.challenge,
              redirect_port: searchParams.redirect_port,
              profile_url: `${window.location.origin}/profile`,
            },
          },
        );
        if (result.redirectUrl) {
          window.location.href = result.redirectUrl;
          return;
        }
      }
      // Use a hard navigation (same behavior as login) to avoid any SPA cache edge cases.
      window.location.href = '/profile';
    } catch (error) {
      setError('root', {
        type: 'manual',
        message: getErrorMessage(error, m.register_error_complete_failed()),
      });
    }
  };

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
              {searchParams.challenge && searchParams.redirect_port && (
                <MinecraftFlowAlert
                  title={m.register_minecraft_title()}
                  challenge={searchParams.challenge}
                  redirectPort={searchParams.redirect_port}
                />
              )}

              <form
                onSubmit={handleSubmit(onSubmit)}
                method="post"
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="username">{m.login_username_label()}</Label>
                  <Input
                    id="username"
                    type="text"
                    {...register('username')}
                    autoComplete="username"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    placeholder={m.register_username_placeholder()}
                    disabled={isSubmitting}
                  />
                  {errors.username && (
                    <p className="text-sm text-destructive">
                      {errors.username.message}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">{m.login_password_label()}</Label>
                  <Input
                    id="password"
                    type="password"
                    {...register('password')}
                    autoComplete="new-password"
                    minLength={6}
                    placeholder={m.settings_create_password_placeholder()}
                    disabled={isSubmitting}
                  />
                  {errors.password && (
                    <p className="text-sm text-destructive">
                      {errors.password.message}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">
                    {m.settings_confirm_password_simple()}
                  </Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    {...register('confirmPassword')}
                    autoComplete="new-password"
                    minLength={6}
                    placeholder={m.settings_confirm_password_simple_placeholder()}
                    disabled={isSubmitting}
                  />
                  {errors.confirmPassword && (
                    <p className="text-sm text-destructive">
                      {errors.confirmPassword.message}
                    </p>
                  )}
                </div>

                {errors.root && (
                  <Alert variant="destructive">
                    <AlertDescription>{errors.root.message}</AlertDescription>
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
              </form>

              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  {m.register_already_have_account()}{' '}
                  <Link
                    to="/login"
                    search={{
                      challenge: searchParams.challenge,
                      redirect_port: searchParams.redirect_port,
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
  validateSearch: (search: Record<string, unknown>): SearchParams =>
    searchParamsSchema.parse(search),
});
