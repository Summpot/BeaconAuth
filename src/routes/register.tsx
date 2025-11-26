import { zodResolver } from '@hookform/resolvers/zod';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { ApiError, apiClient } from '../utils/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ChevronLeft, Loader2, Gamepad2 } from 'lucide-react';

const searchParamsSchema = z.object({
  challenge: z.string().min(1).optional(),
  redirect_port: z.coerce.number().min(1).max(65535).optional(),
});

type SearchParams = z.infer<typeof searchParamsSchema>;

const registerFormSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

type RegisterFormData = z.infer<typeof registerFormSchema>;

const BeaconIcon = ({ className = "w-16 h-16" }: { className?: string }) => (
  <svg className={className} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <title>Beacon</title>
    <rect x="20" y="48" width="24" height="8" fill="#4a4a5a" stroke="#3a3a4a" strokeWidth="1"/>
    <rect x="24" y="40" width="16" height="8" fill="#5a5a6a" stroke="#4a4a5a" strokeWidth="1"/>
    <rect x="26" y="42" width="12" height="4" fill="#a855f7">
      <animate attributeName="opacity" values="0.8;1;0.8" dur="2s" repeatCount="indefinite"/>
    </rect>
    <path d="M32 42 L24 8 L40 8 Z" fill="url(#beamGradientRegister)" opacity="0.6">
      <animate attributeName="opacity" values="0.4;0.7;0.4" dur="2s" repeatCount="indefinite"/>
    </path>
    <path d="M32 42 L28 8 L36 8 Z" fill="url(#beamGradientInnerRegister)" opacity="0.8">
      <animate attributeName="opacity" values="0.6;1;0.6" dur="1.5s" repeatCount="indefinite"/>
    </path>
    <defs>
      <linearGradient id="beamGradientRegister" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#a855f7"/>
        <stop offset="100%" stopColor="#a855f7" stopOpacity="0"/>
      </linearGradient>
      <linearGradient id="beamGradientInnerRegister" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#ffffff"/>
        <stop offset="50%" stopColor="#a855f7"/>
        <stop offset="100%" stopColor="#a855f7" stopOpacity="0"/>
      </linearGradient>
    </defs>
  </svg>
);

function RegisterPage() {
  const searchParams = Route.useSearch();
  const navigate = useNavigate();

  const getErrorMessage = (error: unknown, fallback: string) => {
    if (error instanceof ApiError) {
      const data = error.data as { message?: string } | undefined;
      return data?.message ?? error.message;
    }
    if (error instanceof Error) return error.message;
    return fallback;
  };

  const { register, handleSubmit, formState: { errors, isSubmitting }, setError } = useForm<RegisterFormData>({
    resolver: zodResolver(registerFormSchema),
  });

  const onSubmit = async (data: RegisterFormData) => {
    try {
      await apiClient('/api/v1/register', { method: 'POST', requiresAuth: false, body: { username: data.username, password: data.password } });
    } catch (error) {
      setError('root', { type: 'manual', message: getErrorMessage(error, 'Registration failed') });
      return;
    }

    try {
      if (searchParams.challenge && searchParams.redirect_port) {
        const result = await apiClient<{ redirectUrl?: string }>('/api/v1/minecraft-jwt', {
          method: 'POST',
          body: { challenge: searchParams.challenge, redirect_port: searchParams.redirect_port, profile_url: window.location.origin + '/profile' },
        });
        if (result.redirectUrl) {
          window.location.href = result.redirectUrl;
          return;
        }
      }
      navigate({ to: '/profile' });
    } catch (error) {
      setError('root', { type: 'manual', message: getErrorMessage(error, 'Failed to complete registration') });
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <Link to="/" className="inline-flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors mb-6">
          <ChevronLeft className="h-4 w-4" />
          Back to Home
        </Link>

        <Card>
          <CardHeader className="text-center pb-4">
            <div className="flex justify-center mb-4">
              <BeaconIcon className="w-16 h-16" />
            </div>
            <CardTitle className="text-3xl font-bold">Create Account</CardTitle>
            <CardDescription>Join the BeaconAuth community</CardDescription>
          </CardHeader>

          <CardContent className="space-y-6">
            {searchParams.challenge && searchParams.redirect_port && (
              <Alert>
                <Gamepad2 className="h-4 w-4" />
                <AlertDescription>
                  <div className="space-y-2">
                    <span className="text-primary font-medium">Minecraft Registration</span>
                    <div className="space-y-1 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Challenge:</span>
                        <span className="text-foreground font-mono text-xs">{searchParams.challenge.substring(0, 16)}...</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Port:</span>
                        <span className="text-foreground">{searchParams.redirect_port}</span>
                      </div>
                    </div>
                  </div>
                </AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input id="username" type="text" {...register('username')} placeholder="Choose a username" disabled={isSubmitting} className="bg-background/50 border-input" />
                {errors.username && <p className="text-sm text-destructive">{errors.username.message}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input id="password" type="password" {...register('password')} placeholder="Create a password (min 6 chars)" disabled={isSubmitting} className="bg-background/50 border-input" />
                {errors.password && <p className="text-sm text-destructive">{errors.password.message}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm Password</Label>
                <Input id="confirmPassword" type="password" {...register('confirmPassword')} placeholder="Confirm your password" disabled={isSubmitting} className="bg-background/50 border-input" />
                {errors.confirmPassword && <p className="text-sm text-destructive">{errors.confirmPassword.message}</p>}
              </div>

              {errors.root && <Alert variant="destructive"><AlertDescription>{errors.root.message}</AlertDescription></Alert>}

              <Button type="submit" disabled={isSubmitting} className="w-full">
                {isSubmitting ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Creating Account...</> : 'Create Account'}
              </Button>
            </form>

            <div className="text-center">
              <p className="text-sm text-muted-foreground">
                Already have an account?{' '}
                <Link to="/login" search={{ challenge: searchParams.challenge, redirect_port: searchParams.redirect_port }} className="text-primary hover:text-primary/80 font-medium transition-colors">
                  Sign in
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="mt-6 text-center">
          <p className="text-xs text-muted-foreground">🔒 Your password is securely hashed with bcrypt</p>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/register')({
  component: RegisterPage,
  validateSearch: (search: Record<string, unknown>): SearchParams => searchParamsSchema.parse(search),
});
