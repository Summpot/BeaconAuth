import { Eye, EyeOff } from 'lucide-react';
import { useId, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import * as m from '@/paraglide/messages';

type PasswordFieldProps = Omit<
  React.ComponentProps<typeof Input>,
  'type' | 'id' | 'value' | 'onChange'
> & {
  label: string;
  value: string;
  onChange: (value: string) => void;
  errorMessage?: string;
  isInvalid?: boolean;
};

/**
 * Labeled password input with a show/hide toggle (eye icon).
 * Keeps `autoComplete`, `disabled` and other input props forwarded.
 */
export function PasswordField({
  label,
  value,
  onChange,
  errorMessage,
  isInvalid,
  className,
  ...inputProps
}: PasswordFieldProps) {
  const id = useId();
  const [visible, setVisible] = useState(false);
  const showToggleLabel = visible
    ? m.login_hide_password()
    : m.login_show_password();

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Input
          id={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          aria-invalid={isInvalid}
          className={`pr-10 ${className ?? ''}`}
          {...inputProps}
        />
        <button
          type="button"
          tabIndex={-1}
          aria-label={showToggleLabel}
          onClick={() => setVisible((v) => !v)}
          className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-muted-foreground transition-colors hover:text-foreground focus:outline-none"
        >
          {visible ? (
            <EyeOff className="h-4 w-4" />
          ) : (
            <Eye className="h-4 w-4" />
          )}
        </button>
      </div>
      {isInvalid && errorMessage ? (
        <p className="text-sm text-destructive">{errorMessage}</p>
      ) : null}
    </div>
  );
}
