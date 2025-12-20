import { createFileRoute, Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { apiClient, queryKeys } from '../utils/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Github, KeyRound, Shield, Gamepad2 } from 'lucide-react';

interface UserInfo {
  id: number;
  username: string;
}

// Beacon SVG Component
const BeaconIcon = ({ className = "w-24 h-24" }: { className?: string }) => (
  <svg className={className} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
    <title>Beacon</title>
    <rect x="20" y="48" width="24" height="8" fill="#4a4a5a" stroke="#3a3a4a" strokeWidth="1"/>
    <rect x="24" y="40" width="16" height="8" fill="#5a5a6a" stroke="#4a4a5a" strokeWidth="1"/>
    <rect x="26" y="42" width="12" height="4" fill="#4eecd6">
      <animate attributeName="opacity" values="0.8;1;0.8" dur="2s" repeatCount="indefinite"/>
    </rect>
    <path d="M32 42 L24 8 L40 8 Z" fill="url(#beamGradient)" opacity="0.6">
      <animate attributeName="opacity" values="0.4;0.7;0.4" dur="2s" repeatCount="indefinite"/>
    </path>
    <path d="M32 42 L28 8 L36 8 Z" fill="url(#beamGradientInner)" opacity="0.8">
      <animate attributeName="opacity" values="0.6;1;0.6" dur="1.5s" repeatCount="indefinite"/>
    </path>
    <defs>
      <linearGradient id="beamGradient" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#4eecd6"/>
        <stop offset="100%" stopColor="#4eecd6" stopOpacity="0"/>
      </linearGradient>
      <linearGradient id="beamGradientInner" x1="32" y1="42" x2="32" y2="8" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#ffffff"/>
        <stop offset="50%" stopColor="#4eecd6"/>
        <stop offset="100%" stopColor="#4eecd6" stopOpacity="0"/>
      </linearGradient>
    </defs>
  </svg>
);

function HomePage() {
  const { data: user } = useQuery({
    queryKey: queryKeys.userMe(),
    queryFn: async (): Promise<UserInfo | null> => {
      try {
        return await apiClient<UserInfo>('/api/v1/user/me', { requiresAuth: false });
      } catch {
        return null;
      }
    },
  });

  return (
    <div className="min-h-screen">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <BeaconIcon className="w-10 h-10" />
              <span className="text-2xl font-bold text-primary">BeaconAuth</span>
            </Link>
            
            <div className="flex items-center gap-4">
              {user ? (
                <>
                  <Link to="/profile">
                    <Button variant="ghost">{user.username}</Button>
                  </Link>
                  <Link to="/settings">
                    <Button variant="ghost">Settings</Button>
                  </Link>
                </>
              ) : (
                <>
                  <Link to="/login">
                    <Button variant="ghost">Login</Button>
                  </Link>
                  <Link to="/register">
                    <Button>Get Started</Button>
                  </Link>
                </>
              )}
              <a
                href="https://github.com/Summpot/beacon_auth"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="ghost" size="icon">
                  <Github className="h-5 w-5" />
                </Button>
              </a>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-1 h-[600px] bg-linear-to-b from-transparent via-primary/30 to-transparent blur-sm" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-[500px] bg-linear-to-b from-transparent via-primary/10 to-transparent blur-3xl" />
        
        <div className="container mx-auto px-6 text-center relative">
          <div className="inline-block mb-8">
            <div className="w-32 h-32 mx-auto relative">
              <BeaconIcon className="w-32 h-32" />
              <div className="absolute inset-0 bg-primary/20 rounded-full blur-2xl" />
            </div>
          </div>
          
          <h1 className="text-5xl md:text-7xl font-bold mb-6">
            <span className="text-foreground">Secure Your </span>
            <span className="text-primary">Minecraft Server</span>
          </h1>
          
          <p className="text-xl text-muted-foreground mb-10 max-w-2xl mx-auto leading-relaxed">
            Modern authentication for Minecraft servers. 
            <span className="text-primary"> Password</span>,
            <span className="text-secondary-foreground"> OAuth</span>, and
            <span className="text-muted-foreground"> Passkey</span> support
            with enterprise-grade security.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            {user ? (
              <>
                <Link to="/profile">
                  <Button size="lg">View Profile</Button>
                </Link>
                <Link to="/settings">
                  <Button variant="secondary" size="lg">Manage Settings</Button>
                </Link>
              </>
            ) : (
              <>
                <Link to="/login">
                  <Button size="lg">Login Now</Button>
                </Link>
                <Link to="/register">
                  <Button variant="secondary" size="lg">Create Account</Button>
                </Link>
              </>
            )}
          </div>

          {/* Quick stats */}
          <div className="mt-16 grid grid-cols-3 gap-8 max-w-lg mx-auto">
            <div className="text-center">
              <Badge variant="outline" className="text-lg px-3 py-1">ES256</Badge>
              <div className="text-sm text-muted-foreground mt-2">JWT Signing</div>
            </div>
            <div className="text-center">
              <Badge variant="outline" className="text-lg px-3 py-1">OAuth 2</Badge>
              <div className="text-sm text-muted-foreground mt-2">Providers</div>
            </div>
            <div className="text-center">
              <Badge variant="outline" className="text-lg px-3 py-1">WebAuthn</Badge>
              <div className="text-sm text-muted-foreground mt-2">Passkeys</div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4">
              Why <span className="text-primary">BeaconAuth</span>?
            </h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              Built for Minecraft server administrators who demand security without sacrificing user experience.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto">
            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="p-6">
                <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center mb-4">
                  <KeyRound className="h-6 w-6 text-primary" />
                </div>
                <h3 className="text-xl font-bold text-foreground mb-2">Multi-Auth Support</h3>
                <p className="text-muted-foreground text-sm">
                  Traditional passwords, OAuth (GitHub & Google), and cutting-edge WebAuthn passkeys for the ultimate flexibility.
                </p>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="p-6">
                <div className="w-12 h-12 rounded-xl bg-secondary/20 flex items-center justify-center mb-4">
                  <Shield className="h-6 w-6 text-secondary-foreground" />
                </div>
                <h3 className="text-xl font-bold text-foreground mb-2">Enterprise Security</h3>
                <p className="text-muted-foreground text-sm">
                  ES256 JWT signing, secure HttpOnly cookies, PKCE OAuth flows, and automatic token rotation.
                </p>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="p-6">
                <div className="w-12 h-12 rounded-xl bg-muted/50 flex items-center justify-center mb-4">
                  <Gamepad2 className="h-6 w-6 text-muted-foreground" />
                </div>
                <h3 className="text-xl font-bold text-foreground mb-2">Seamless Integration</h3>
                <p className="text-muted-foreground text-sm">
                  Cross-platform Minecraft mod for Fabric & Forge with automatic authentication and server verification.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Tech Stack Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6">
          <Card className="bg-card/50 border-border max-w-4xl mx-auto">
            <CardContent className="p-8 md:p-12">
              <h2 className="text-2xl md:text-3xl font-bold text-foreground mb-8 text-center">
                Built with Modern Stack
              </h2>
              
              <div className="grid md:grid-cols-2 gap-8">
                <div>
                  <h3 className="text-primary font-semibold mb-4 flex items-center gap-2">
                    <span className="w-2 h-2 bg-primary rounded-full" />
                    Backend
                  </h3>
                  <ul className="space-y-3 text-muted-foreground">
                    <li className="flex items-center gap-3">
                      <span className="text-orange-400">🦀</span>
                      <span>Rust with Actix-web</span>
                    </li>
                    <li className="flex items-center gap-3">
                      <span className="text-blue-400">🗄️</span>
                      <span>Sea-ORM database layer</span>
                    </li>
                    <li className="flex items-center gap-3">
                      <span className="text-green-400">🔑</span>
                      <span>ES256 JWT + WebAuthn</span>
                    </li>
                  </ul>
                </div>
                
                <div>
                  <h3 className="text-muted-foreground font-semibold mb-4 flex items-center gap-2">
                    <span className="w-2 h-2 bg-muted-foreground rounded-full" />
                    Frontend & Mod
                  </h3>
                  <ul className="space-y-3 text-muted-foreground">
                    <li className="flex items-center gap-3">
                      <span className="text-primary">⚛️</span>
                      <span>React + TanStack Router</span>
                    </li>
                    <li className="flex items-center gap-3">
                      <span className="text-yellow-400">⚡</span>
                      <span>Rsbuild for fast bundling</span>
                    </li>
                    <li className="flex items-center gap-3">
                      <span className="text-muted-foreground">🎮</span>
                      <span>Kotlin Architectury (Fabric/Forge)</span>
                    </li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6 text-center">
          <Card className="border-primary/20 inline-block">
            <CardContent className="p-8">
              <h2 className="text-2xl md:text-3xl font-bold text-foreground mb-4">
                Ready to Secure Your Server?
              </h2>
              <p className="text-muted-foreground mb-6">
                Get started with BeaconAuth today and enjoy peace of mind.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <a
                  href="https://github.com/Summpot/beacon_auth"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Button size="lg">
                    <Github className="mr-2 h-5 w-5" />
                    View on GitHub
                  </Button>
                </a>
                <Link to="/login">
                  <Button variant="secondary" size="lg">Try Demo</Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 border-t border-border">
        <div className="container mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-muted-foreground">
              <BeaconIcon className="w-6 h-6 opacity-50" />
              <span className="text-sm">BeaconAuth © 2024</span>
            </div>
            <div className="flex items-center gap-6 text-sm text-muted-foreground">
              <span>Open Source</span>
              <span>•</span>
              <span>MIT License</span>
              <span>•</span>
              <a 
                href="https://github.com/Summpot/beacon_auth"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-primary transition-colors"
              >
                Contribute
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export const Route = createFileRoute('/')({
  component: HomePage,
});
