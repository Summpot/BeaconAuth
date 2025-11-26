import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { startRegistration, type PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/browser';
import { ApiError, apiClient } from '../utils/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { ChevronLeft, Loader2, Plus, Key, X, Lightbulb, Trash2 } from 'lucide-react';

const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string().min(6, 'Password must be at least 6 characters'),
  confirmPassword: z.string().min(1, 'Please confirm your password'),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

type PasswordChangeData = z.infer<typeof passwordChangeSchema>;

interface UserInfo { id: number; username: string; }
interface PasskeyInfo { id: number; name: string; created_at: string; last_used_at: string | null; }

const getErrorMessage = (error: unknown, fallback = 'Failed to process request') => {
  if (error instanceof ApiError) {
    const data = error.data as { message?: string } | undefined;
    return data?.message ?? error.message;
  }
  if (error instanceof Error) return error.message;
  return fallback;
};

const BeaconIcon = ({ className = "w-16 h-16" }: { className?: string }) => (
  <svg className={className} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <title>Beacon</title>
    <rect x="20" y="48" width="24" height="8" fill="#4a4a5a" stroke="#3a3a4a" strokeWidth="1"/>
    <rect x="24" y="40" width="16" height="8" fill="#5a5a6a" stroke="#4a4a5a" strokeWidth="1"/>
    <rect x="26" y="42" width="12" height="4" fill="#4eecd6">
      <animate attributeName="opacity" values="0.8;1;0.8" dur="2s" repeatCount="indefinite"/>
    </rect>
    <path d="M32 42 L24 8 L40 8 Z" fill="url(#beamGradientSettings)" opacity="0.6">
      <animate attributeName="opacity" values="0.4;0.7;0.4" dur="2s" repeatCount="indefinite"/>
    </path>
    <path d="M32 42 L28 8 L36 8 Z" fill="url(#beamGradientInnerSettings)" opacity="0.8">
      <animate attributeName="opacity" values="0.6;1;0.6" dur="1.5s" repeatCount="indefinite"/>
    </path>
    <defs>
      <linearGradient id="beamGradientSettings" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#4eecd6"/>
        <stop offset="100%" stopColor="#4eecd6" stopOpacity="0"/>
      </linearGradient>
      <linearGradient id="beamGradientInnerSettings" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#ffffff"/>
        <stop offset="50%" stopColor="#4eecd6"/>
        <stop offset="100%" stopColor="#4eecd6" stopOpacity="0"/>
      </linearGradient>
    </defs>
  </svg>
);

function SettingsPage() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [showPasskeyModal, setShowPasskeyModal] = useState(false);
  const [passkeyName, setPasskeyName] = useState('');

  const { register, handleSubmit, formState: { errors, isSubmitting }, reset } = useForm<PasswordChangeData>({
    resolver: zodResolver(passwordChangeSchema),
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const userData = await apiClient<UserInfo>('/api/v1/user/me');
        setUser(userData);
        const passkeysData = await apiClient<{ passkeys: PasskeyInfo[] }>('/api/v1/passkey/list');
        setPasskeys(passkeysData.passkeys || []);
      } catch (error) {
        console.error('Failed to load settings data', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const onPasswordChange = async (data: PasswordChangeData) => {
    try {
      await apiClient('/api/v1/user/change-password', {
        method: 'POST',
        body: { current_password: data.currentPassword, new_password: data.newPassword },
      });
      setMessage({ type: 'success', text: 'Password changed successfully!' });
      reset();
    } catch (error) {
      setMessage({ type: 'error', text: getErrorMessage(error, 'Failed to connect to server') });
    }
  };

  const handlePasskeyModalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = passkeyName.trim();
    if (!name) {
      setMessage({ type: 'error', text: 'Passkey name is required' });
      return;
    }
    try {
      const data = await apiClient<{ creation_options: { publicKey: PublicKeyCredentialCreationOptionsJSON } }>(
        '/api/v1/passkey/register/start', { method: 'POST', body: { name } }
      );
      const credential = await startRegistration({ optionsJSON: data.creation_options.publicKey });
      await apiClient('/api/v1/passkey/register/finish', { method: 'POST', body: { credential, name } });
      setMessage({ type: 'success', text: 'Passkey registered successfully!' });
      setShowPasskeyModal(false);
      setPasskeyName('');
      const passkeysData = await apiClient<{ passkeys: PasskeyInfo[] }>('/api/v1/passkey/list');
      setPasskeys(passkeysData.passkeys || []);
    } catch (error) {
      console.error('Passkey registration failed:', error);
      setMessage({ type: 'error', text: `Failed to register passkey: ${getErrorMessage(error, 'Unknown error')}` });
      setShowPasskeyModal(false);
      setPasskeyName('');
    }
  };

  const handleDeletePasskey = async (id: number, name: string) => {
    if (!confirm(`Are you sure you want to delete passkey "${name}"?`)) return;
    try {
      await apiClient(`/api/v1/passkey/${id}`, { method: 'DELETE' });
      setMessage({ type: 'success', text: 'Passkey deleted successfully!' });
      setPasskeys(passkeys.filter((p) => p.id !== id));
    } catch (error) {
      setMessage({ type: 'error', text: `Failed to delete passkey: ${getErrorMessage(error, 'Unknown error')}` });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="text-muted-foreground">Loading...</span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="w-full max-w-md">
          <Card className="text-center">
            <CardContent className="pt-6">
              <div className="inline-block mb-6">
                <BeaconIcon className="w-20 h-20 opacity-50" />
              </div>
              <CardTitle className="text-2xl font-bold mb-4">Not Authenticated</CardTitle>
              <CardDescription className="mb-6">Please log in to access settings.</CardDescription>
              <Button asChild><Link to="/login">Sign In</Link></Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-4">
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <BeaconIcon className="w-8 h-8" />
              <span className="text-xl text-primary font-bold">BeaconAuth</span>
            </Link>
            <Button variant="ghost" asChild><Link to="/profile">Profile</Link></Button>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto pt-24 pb-8">
        <div className="mb-8">
          <Link to="/profile" className="inline-flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors mb-4">
            <ChevronLeft className="h-4 w-4" />
            Back to Profile
          </Link>
          <h1 className="text-3xl font-bold">Profile Settings</h1>
          <p className="text-muted-foreground mt-2">Manage your password and passkeys for <span className="text-primary">{user.username}</span></p>
        </div>

        {message && (
          <Alert variant={message.type === 'success' ? 'default' : 'destructive'} className="mb-6">
            <AlertDescription className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-xl">{message.type === 'success' ? '✓' : '✗'}</span>
                <p>{message.text}</p>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setMessage(null)}><X className="h-4 w-4" /></Button>
            </AlertDescription>
          </Alert>
        )}

        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-xl font-bold flex items-center gap-3">
              <span className="w-2 h-2 bg-primary rounded-full" />Change Password
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onPasswordChange)} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="currentPassword">Current Password</Label>
                <Input id="currentPassword" type="password" {...register('currentPassword')} placeholder="Enter current password" disabled={isSubmitting} className="bg-background/50" />
                {errors.currentPassword && <p className="text-sm text-destructive">{errors.currentPassword.message}</p>}
              </div>
              <div className="space-y-2">
                <Label htmlFor="newPassword">New Password</Label>
                <Input id="newPassword" type="password" {...register('newPassword')} placeholder="Enter new password (min 6 characters)" disabled={isSubmitting} className="bg-background/50" />
                {errors.newPassword && <p className="text-sm text-destructive">{errors.newPassword.message}</p>}
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm New Password</Label>
                <Input id="confirmPassword" type="password" {...register('confirmPassword')} placeholder="Confirm new password" disabled={isSubmitting} className="bg-background/50" />
                {errors.confirmPassword && <p className="text-sm text-destructive">{errors.confirmPassword.message}</p>}
              </div>
              <Button type="submit" disabled={isSubmitting} className="w-full">
                {isSubmitting ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Changing Password...</> : 'Change Password'}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-xl font-bold flex items-center gap-3">
                  <span className="w-2 h-2 bg-primary rounded-full" />Passkeys
                </CardTitle>
                <CardDescription>Use biometric authentication for passwordless login</CardDescription>
              </div>
              <Button onClick={() => setShowPasskeyModal(true)}><Plus className="h-4 w-4 mr-2" />Add Passkey</Button>
            </div>
          </CardHeader>
          <CardContent>
            {passkeys.length === 0 ? (
              <div className="text-center py-12 border-2 border-dashed border-border rounded-xl">
                <Key className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <p className="text-muted-foreground mb-2">No passkeys registered yet</p>
                <p className="text-sm text-muted-foreground">Add a passkey for faster, more secure authentication</p>
              </div>
            ) : (
              <div className="space-y-3">
                {passkeys.map((passkey) => (
                  <div key={passkey.id} className="flex items-center justify-between p-4 rounded-xl border border-border bg-card/50 hover:border-primary/30 transition-colors">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                        <Key className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-semibold">{passkey.name}</h3>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                          <span>Created: {new Date(passkey.created_at).toLocaleDateString()}</span>
                          {passkey.last_used_at && <span>Last used: {new Date(passkey.last_used_at).toLocaleDateString()}</span>}
                        </div>
                      </div>
                    </div>
                    <Button variant="destructive" size="sm" onClick={() => handleDeletePasskey(passkey.id, passkey.name)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}

            <Alert className="mt-6">
              <Lightbulb className="h-4 w-4" />
              <AlertDescription>
                <h3 className="font-semibold mb-1">What are passkeys?</h3>
                <p className="text-sm text-muted-foreground">
                  Passkeys are a secure, passwordless authentication method that uses your device's biometric authentication (fingerprint, face recognition) or PIN. They're more secure than passwords and easier to use.
                </p>
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>

        <Dialog open={showPasskeyModal} onOpenChange={setShowPasskeyModal}>
          <DialogContent className="bg-card border-border">
            <DialogHeader>
              <DialogTitle>Add New Passkey</DialogTitle>
              <DialogDescription>Give your passkey a memorable name to identify this device.</DialogDescription>
            </DialogHeader>
            <form onSubmit={handlePasskeyModalSubmit}>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="passkeyName">Passkey Name</Label>
                  <Input id="passkeyName" type="text" value={passkeyName} onChange={(e) => setPasskeyName(e.target.value)} placeholder='e.g., "My Phone", "YubiKey"' className="bg-background/50" />
                </div>
                <div className="flex gap-3">
                  <Button type="button" variant="secondary" className="flex-1" onClick={() => { setShowPasskeyModal(false); setPasskeyName(''); }}>Cancel</Button>
                  <Button type="submit" className="flex-1">Continue</Button>
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
