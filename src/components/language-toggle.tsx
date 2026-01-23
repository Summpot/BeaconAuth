import { Languages } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import * as m from '@/paraglide/messages';
import { setLocale } from '@/paraglide/runtime';

export function LanguageToggle() {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
          <Languages className="h-[1.2rem] w-[1.2rem]" />
          <span className="sr-only">{m.aria_change_language()}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => setLocale('en')}>
          English
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocale('fr')}>
          Français
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocale('de')}>
          Deutsch
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocale('ja')}>
          日本語
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocale('ko')}>
          한국어
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocale('zh-CN')}>
          中文 (简体)
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocale('zh-TW')}>
          中文 (繁體)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
