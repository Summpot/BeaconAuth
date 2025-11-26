import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { apiClient } from '../utils/api';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Loader2, CheckCircle2, XCircle, Home } from 'lucide-react';

// Beacon SVG Component
const BeaconIcon = ({ className = "w-16 h-16" }: { className?: string }) => (
  <svg className={className} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <title>Beacon</title>
    <rect x="20" y="48" width="24" height="8" fill="#4a4a5a" stroke="#3a3a4a" strokeWidth="1"/>
    <rect x="24" y="40" width="16" height="8" fill="#5a5a6a" stroke="#4a4a5a" strokeWidth="1"/>
    <rect x="26" y="42" width="12" height="4" fill="#4eecd6">
      <animate attributeName="opacity" values="0.8;1;0.8" dur="2s" repeatCount="indefinite"/>
    </rect>
    <path d="M32 42 L24 8 L40 8 Z" fill="url(#beamGradientOAuth)" opacity="0.6">
      <animate attributeName="opacity" values="0.4;0.7;0.4" dur="2s" repeatCount="indefinite"/>
    </path>
    <path d="M32 42 L28 8 L36 8 Z" fill="url(#beamGradientInnerOAuth)" opacity="0.8">
      <animate attributeName="opacity" values="0.6;1;0.6" dur="1.5s" repeatCount="indefinite"/>
    </path>
    <defs>
      <linearGradient id="beamGradientOAuth" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#4eecd6"/>
        <stop offset="100%" stopColor="#4eecd6" stopOpacity="0"/>
      </linearGradient>
      <linearGradient id="beamGradientInnerOAuth" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#ffffff"/>
        <stop offset="50%" stopColor="#4eecd6"/>
        <stop offset="100%" stopColor="#4eecd6" stopOpacity="0"/>
      </linearGradient>
    </defs>
  </svg>
);

function OAuthCompletePage() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('Processing authentication...');

  useEffect(() => {
    const completeAuth = async () => {
      try {
        // Retrieve saved parameters from sessionStorage
        const challenge = sessionStorage.getItem('minecraft_challenge');
        const redirectPortStr = sessionStorage.getItem('minecraft_redirect_port');

        // Check if we're in Minecraft mode or normal web mode
        if (!challenge || !redirectPortStr) {
          // Normal web OAuth login - redirect to profile page
          setStatus('success');
          setMessage('Authentication successful! Redirecting to profile...');
          
          // Clean up any partial sessionStorage data
          sessionStorage.removeItem('minecraft_challenge');
          sessionStorage.removeItem('minecraft_redirect_port');
          
          setTimeout(() => {
            window.location.href = '/profile';
          }, 1000);
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
              profile_url: window.location.origin + '/profile',
            },
          }
        );

        // Clean up sessionStorage
        sessionStorage.removeItem('minecraft_challenge');
        sessionStorage.removeItem('minecraft_redirect_port');

        if (result?.redirectUrl) {
          setStatus('success');
          setMessage('Authentication successful! Redirecting to Minecraft...');
          setTimeout(() => {
            window.location.href = result.redirectUrl as string;
          }, 1000);
        }
      } catch (error) {
        console.error('OAuth completion error:', error);
        setStatus('error');
        setMessage('An error occurred during authentication. Please try again.');
      }
    };

    completeAuth();
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <Card>
          <CardContent className="p-8">
            <div className="text-center">
              {status === 'loading' && (
                <>
                  <div className="inline-block mb-6">
                    <BeaconIcon className="w-24 h-24" />
                  </div>
                  <h2 className="text-2xl font-bold text-foreground mb-4">
                    Processing...
                  </h2>
                  <div className="flex items-center justify-center gap-3 mb-4">
                    <Loader2 className="h-5 w-5 text-primary animate-spin" />
                    <span className="text-muted-foreground">Please wait</span>
                  </div>
                </>
              )}

              {status === 'success' && (
                <>
                  <div className="inline-block mb-6">
                    <div className="w-24 h-24 rounded-full bg-green-500/20 flex items-center justify-center border-2 border-green-500/50">
                      <CheckCircle2 className="w-12 h-12 text-green-500" />
                    </div>
                  </div>
                  <h2 className="text-2xl font-bold text-green-500 mb-4">
                    Success!
                  </h2>
                </>
              )}

              {status === 'error' && (
                <>
                  <div className="inline-block mb-6">
                    <div className="w-24 h-24 rounded-full bg-destructive/20 flex items-center justify-center border-2 border-destructive/50">
                      <XCircle className="w-12 h-12 text-destructive" />
                    </div>
                  </div>
                  <h2 className="text-2xl font-bold text-destructive mb-4">
                    Authentication Failed
                  </h2>
                </>
              )}

              <p className="text-muted-foreground mb-6">{message}</p>

              {status === 'error' && (
                <div className="flex flex-col gap-3">
                  <Link to="/login">
                    <Button className="w-full">Try Again</Button>
                  </Link>
                  <Link to="/">
                    <Button variant="outline" className="w-full">
                      <Home className="mr-2 h-4 w-4" />
                      Back to Home
                    </Button>
                  </Link>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/oauth-complete')({
  component: OAuthCompletePage,
});
