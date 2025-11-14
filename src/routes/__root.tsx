import { createRootRoute, Outlet } from '@tanstack/react-router';

const RootLayout = () => (
  <div className="min-h-screen bg-linear-to-br from-blue-50 to-indigo-100">
    <Outlet />
  </div>
);

export const Route = createRootRoute({ component: RootLayout });
