import { createFileRoute } from '@tanstack/react-router';

function ErrorPage() {
  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-lg shadow-xl p-8">
          <div className="text-center">
            <div className="text-6xl mb-4">⚠️</div>
            <h1 className="text-2xl font-bold text-gray-900 mb-4">
              Invalid Request
            </h1>
            <p className="text-gray-600 mb-4">
              This page requires valid challenge and redirect_port parameters.
              <br />
              Please access this page through the Minecraft mod.
            </p>
            <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">
              Missing required parameters in URL
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/error')({
  component: ErrorPage,
});
