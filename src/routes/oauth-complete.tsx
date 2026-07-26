import { createFileRoute, Link } from '@tanstack/react-router';
import { CheckCircle2, Home, Loader2, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { PageLoader } from '@/components/ui/page-loader';
import * as m from '@/paraglide/messages';
import { apiClient } from '../utils/api';

function OAuthCompletePage() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>(
    'loading',
  );
  const [message, setMessage] = useState(
    m.oauth_complete_processing_authentication(),
  );
  const [target, setTarget] = useState<'profile' | 'minecraft' | null>(null);

  useEffect(() => {
    const completeAuth = async () => {
      try {
        // Retrieve saved parameters from sessionStorage
        const challenge = sessionStorage.getItem('minecraft_challenge');
        const redirectPortStr = sessionStorage.getItem(
          'minecraft_redirect_port',
        );

        // Check if we're in Minecraft mode or normal web mode
        if (!challenge || !redirectPortStr) {
          // Normal web OAuth login - redirect to profile page
          setStatus('success');
          setTarget('profile');
          setMessage(m.oauth_complete_auth_success_profile());

          // Clean up any partial sessionStorage data
          sessionStorage.removeItem('minecraft_challenge');
          sessionStorage.removeItem('minecraft_redirect_port');

          setTimeout(() => {
            window.location.href = '/profile';
          }, 750);
          return;
        }

        // Minecraft mode - generate JWT and redirect to mod
        const redirect_port = parseInt(redirectPortStr, 10);

        // Get Minecraft JWT using the session cookie (set by OAuth callback)
        const result = await apiClient<{ redirectUrl?: string }>(
          '/api/v1/minecraft-jwt',
          {
            method: 'POST',
            body: {
              challenge,
              redirect_port,
              profile_url: `${window.location.origin}/profile`,
            },
          },
        );

        // Clean up sessionStorage
        sessionStorage.removeItem('minecraft_challenge');
        sessionStorage.removeItem('minecraft_redirect_port');

        if (result?.redirectUrl) {
          setStatus('success');
          setTarget('minecraft');
          setMessage(m.oauth_complete_auth_success_minecraft());
          setTimeout(() => {
            window.location.href = result.redirectUrl as string;
          }, 750);
        }
      } catch (error) {
        console.error('OAuth completion error:', error);
        setStatus('error');
        setTarget(null);
        setMessage(m.oauth_complete_auth_error());
      }
    };

    completeAuth();
  }, []);

  if (status === 'loading') {
    return (
      <PageLoader
        title={m.oauth_complete_title_completing_sign_in()}
        description={message}
        icon={<BeaconIcon className="size-6 text-primary" />}
        compact
      />
    );
  }

  const isSuccess = status === 'success';
  const title = isSuccess
    ? m.oauth_complete_title_signed_in()
    : m.oauth_complete_title_auth_failed();
  const subtitle =
    target === 'minecraft'
      ? m.oauth_complete_subtitle_minecraft()
      : target === 'profile'
        ? m.oauth_complete_subtitle_profile()
        : m.oauth_complete_subtitle_error();

  return (
    <div className="flex min-h-full items-center justify-center bg-surface p-4">
      <div className="w-full max-w-lg">
        <Card className="rounded-xl">
          <CardHeader className="text-center">
            <div className="relative mx-auto">
              <div
                className={
                  isSuccess
                    ? 'flex size-20 items-center justify-center rounded-full bg-primary-container text-on-primary-container'
                    : 'flex size-20 items-center justify-center rounded-full bg-error-container text-on-error-container'
                }
              >
                {isSuccess ? (
                  <CheckCircle2 className="size-10" />
                ) : (
                  <XCircle className="size-10" />
                )}
              </div>
            </div>

            <CardTitle className="text-headline-sm">{title}</CardTitle>
            <CardDescription className="text-body-lg">
              {subtitle}
            </CardDescription>
          </CardHeader>

          <CardContent className="pt-0">
            <div className="rounded-md bg-surface-container-high px-4 py-3">
              <div className="flex items-center justify-center gap-3 text-body-md text-on-surface-variant">
                {isSuccess ? (
                  <Loader2 className="size-4 animate-spin text-primary" />
                ) : null}
                <span className="leading-relaxed">{message}</span>
              </div>
            </div>
          </CardContent>

          {status === 'error' ? (
            <CardFooter className="flex flex-col gap-3 sm:flex-row sm:justify-end">
              <Button asChild variant="text" className="w-full sm:w-auto">
                <Link to="/">
                  <Home />
                  {m.oauth_complete_button_back_home()}
                </Link>
              </Button>
              <Button asChild className="w-full sm:w-auto">
                <Link to="/login">{m.oauth_complete_button_try_again()}</Link>
              </Button>
            </CardFooter>
          ) : null}
        </Card>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/oauth-complete')({
  component: OAuthCompletePage,
});
