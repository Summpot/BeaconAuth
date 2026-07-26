import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * Bare Material Design 3 filled text-field input.
 *
 * Shares the `.m3-field-input` container styling but keeps the placeholder
 * visible, since there is no floating label to take its place. Prefer
 * `TextField` — which adds the label, active indicator and supporting text —
 * unless you need to compose the field yourself.
 */
function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "m3-field-input py-0 placeholder:text-on-surface-variant",
        "focus:border-b-primary aria-invalid:border-b-error",
        "file:inline-flex file:h-8 file:border-0 file:bg-transparent file:text-label-lg file:text-on-surface",
        className
      )}
      {...props}
    />
  )
}

export { Input }
