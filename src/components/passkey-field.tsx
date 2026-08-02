import { useId, useState } from 'react';
import { PasswordField } from '@/components/password-field';

type PasskeyFieldProps = {
  label: string;
  onChange: (value: string) => void;
  errorMessage?: string;
  isInvalid?: boolean;
};

/**
 * Password input that reports its state in a format usable by the
 * confirm-password validator: empty until typed, then the typed value.
 */
export function PasskeyField({
  label,
  onChange,
  errorMessage,
  isInvalid,
}: PasskeyFieldProps) {
  const id = useId();
  const [confirm, setConfirm] = useState('');

  return (
    <div className="space-y-2">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <PasswordField
        label={label}
        value={confirm}
        onChange={(v) => {
          setConfirm(v);
          onChange(v);
        }}
        errorMessage={errorMessage}
        isInvalid={isInvalid}
      />
    </div>
  );
}
