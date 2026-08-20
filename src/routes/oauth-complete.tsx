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

function OAuthCompletePage() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>(
    'loading',
  );
  const [message, setMessage] = useState(
    m.oauth_complete_processing_authentication(),
  );
  const [target, setTarget] = useState<'settings' | 'minecraft' | null>(null);

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
          // Normal web OAuth login - redirect to settings page
          setStatus('success');
          setTarget('settings');
          setMessage(m.oauth_complete_auth_success_settings());

          // Clean up any partial sessionStorage data
          sessionStorage.removeItem('minecraft_challenge');
          sessionStorage.removeItem('minecraft_redirect_port');

          setTimeout(() => {
            window.location.href = '/settings';
          }, 750);
          return;
        }

        // Minecraft mode: the OIDC authorization code was returned to the mod's
        // loopback callback. The mod client exchanges it at the token endpoint
        // directly, so there is nothing left to do in the browser.
        sessionStorage.removeItem('minecraft_challenge');
        sessionStorage.removeItem('minecraft_redirect_port');

        setStatus('success');
        setTarget('minecraft');
        setMessage(m.oauth_complete_auth_success_minecraft());
        setTimeout(() => {
          window.location.href = '/settings';
        }, 750);
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
      : target === 'settings'
        ? m.oauth_complete_subtitle_settings()
        : m.oauth_complete_subtitle_error();

  return (
    <div className="min-h-full flex items-center justify-center p-4 bg-background">
      <div className="w-full max-w-lg">
        <Card className="border-0 shadow-lg bg-card/80 backdrop-blur supports-backdrop-filter:bg-card/70">
          <CardHeader className="text-center">
            <div className="mx-auto relative">
              <div
                className={
                  isSuccess
                    ? 'absolute -inset-3 rounded-full bg-green-500/15 blur'
                    : 'absolute -inset-3 rounded-full bg-destructive/15 blur'
                }
              />
              <div
                className={
                  isSuccess
                    ? 'relative size-20 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center'
                    : 'relative size-20 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center'
                }
              >
                {isSuccess ? (
                  <CheckCircle2 className="size-10 text-green-600 dark:text-green-400" />
                ) : (
                  <XCircle className="size-10 text-destructive" />
                )}
              </div>
            </div>

            <CardTitle className="text-2xl font-bold tracking-tight">
              {title}
            </CardTitle>
            <CardDescription className="text-base">{subtitle}</CardDescription>
          </CardHeader>

          <CardContent className="pt-0">
            <div className="rounded-lg border bg-background/40 px-4 py-3">
              <div className="flex items-center justify-center gap-3 text-sm text-muted-foreground">
                {isSuccess ? (
                  <Loader2 className="h-4 w-4 animate-spin text-primary" />
                ) : null}
                <span className="leading-relaxed">{message}</span>
              </div>
            </div>
          </CardContent>

          {status === 'error' ? (
            <CardFooter className="flex flex-col sm:flex-row gap-3">
              <Button asChild className="w-full sm:w-auto">
                <Link to="/login">{m.oauth_complete_button_try_again()}</Link>
              </Button>
              <Button asChild variant="outline" className="w-full sm:w-auto">
                <Link to="/">
                  <Home className="mr-2 h-4 w-4" />
                  {m.oauth_complete_button_back_home()}
                </Link>
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
