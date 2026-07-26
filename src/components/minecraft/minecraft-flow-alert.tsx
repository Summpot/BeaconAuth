import { Gamepad2 } from 'lucide-react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import * as m from '@/paraglide/messages';

export function MinecraftFlowAlert({ title }: { title: string }) {
  return (
    <Alert variant="info">
      <Gamepad2 />
      <AlertDescription>
        <div className="space-y-1">
          <span className="text-title-sm">{title}</span>
          <p className="text-body-md opacity-90">{m.minecraft_flow_desc()}</p>
        </div>
      </AlertDescription>
    </Alert>
  );
}
