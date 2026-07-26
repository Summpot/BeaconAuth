import { cva, type VariantProps } from "class-variance-authority"
import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * Material Design 3 banner.
 * Semantics are carried by the tonal container roles rather than by borders,
 * so every variant keeps a guaranteed on-colour contrast pair.
 */
const alertVariants = cva(
  [
    "relative grid w-full items-start gap-y-1 rounded-md px-4 py-3 text-body-md",
    "grid-cols-[0_1fr] has-[>svg]:grid-cols-[calc(var(--spacing)*5)_1fr] has-[>svg]:gap-x-4",
    "[&>svg]:size-5 [&>svg]:translate-y-0.5 [&>svg]:text-current",
  ],
  {
    variants: {
      variant: {
        default: "bg-surface-container-high text-on-surface",
        primary: "bg-primary-container text-on-primary-container",
        success: "bg-primary-container text-on-primary-container",
        info: "bg-secondary-container text-on-secondary-container",
        warning: "bg-tertiary-container text-on-tertiary-container",
        destructive: "bg-error-container text-on-error-container",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Alert({
  className,
  variant,
  ...props
}: React.ComponentProps<"div"> & VariantProps<typeof alertVariants>) {
  return (
    <div
      data-slot="alert"
      role="alert"
      className={cn(alertVariants({ variant }), className)}
      {...props}
    />
  )
}

function AlertTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-title"
      className={cn("col-start-2 min-h-5 text-title-sm", className)}
      {...props}
    />
  )
}

function AlertDescription({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-description"
      className={cn(
        "col-start-2 grid justify-items-start gap-1 text-body-md [&_p]:leading-relaxed",
        className
      )}
      {...props}
    />
  )
}

export { Alert, AlertDescription, AlertTitle, alertVariants }
