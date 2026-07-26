import * as React from "react"

import { cn } from "@/lib/utils"

type TextFieldProps = {
  /** Floating label. Rests inside the field when empty, floats on focus/fill. */
  label: string
  /** Persistent helper copy rendered below the field. */
  supportingText?: React.ReactNode
  /** Replaces the supporting text and switches the field to the error state. */
  errorText?: React.ReactNode
  /** Trailing icon slot rendered inside the container (e.g. an info button). */
  trailing?: React.ReactNode
  containerClassName?: string
} & Omit<React.ComponentProps<"input">, "id"> & { id: string }

/**
 * Material Design 3 filled text field.
 *
 * Container is `surface-container-highest` with 4dp top corners and a bottom
 * active indicator that thickens to 2dp in primary on focus (error in error).
 * The label animates between the resting and floating positions, and the
 * placeholder is only revealed once the label has floated — both per spec.
 * The stateful styling lives in `styles.css` under `.m3-field-*`.
 */
function TextField({
  label,
  supportingText,
  errorText,
  trailing,
  className,
  containerClassName,
  id,
  disabled,
  ...props
}: TextFieldProps) {
  const invalid = Boolean(errorText)
  const describedById = `${id}-supporting`
  const hasSupporting = Boolean(errorText ?? supportingText)

  return (
    <div className={cn("flex flex-col", containerClassName)}>
      <div className="m3-field">
        <input
          id={id}
          data-slot="text-field-input"
          aria-invalid={invalid || undefined}
          aria-describedby={hasSupporting ? describedById : undefined}
          disabled={disabled}
          // A non-empty placeholder is required for `:placeholder-shown` to
          // track emptiness; it stays transparent until the label floats.
          placeholder={props.placeholder ?? " "}
          className={cn("m3-field-input", trailing && "pe-14", className)}
          {...props}
        />

        <label
          htmlFor={id}
          className={cn("m3-field-label", trailing && "max-w-[calc(100%-4rem)]")}
        >
          {label}
        </label>

        <span aria-hidden="true" className="m3-field-indicator" />

        {trailing ? (
          <div className="absolute end-2 top-1/2 flex -translate-y-1/2 items-center text-on-surface-variant">
            {trailing}
          </div>
        ) : null}
      </div>

      {hasSupporting ? (
        <p
          id={describedById}
          className={cn(
            "mt-1 px-4 text-body-sm",
            invalid ? "text-error" : "text-on-surface-variant"
          )}
        >
          {errorText ?? supportingText}
        </p>
      ) : null}
    </div>
  )
}

export { TextField }
