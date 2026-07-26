import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * Material Design 3 badge / static chip.
 * Uses the 8dp small-corner shape and the label-medium type role.
 */
const badgeVariants = cva(
  [
    "inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden whitespace-nowrap",
    "rounded-sm px-2 py-1 text-label-md",
    "[&>svg]:pointer-events-none [&>svg]:size-3.5",
    "transition-colors duration-200 ease-standard",
  ],
  {
    variants: {
      variant: {
        default:
          "bg-secondary-container text-on-secondary-container [a&]:hover:bg-secondary-container/80",
        secondary:
          "bg-surface-container-highest text-on-surface-variant [a&]:hover:bg-surface-container-high",
        primary:
          "bg-primary-container text-on-primary-container [a&]:hover:bg-primary-container/80",
        tertiary:
          "bg-tertiary-container text-on-tertiary-container [a&]:hover:bg-tertiary-container/80",
        destructive:
          "bg-error-container text-on-error-container [a&]:hover:bg-error-container/80",
        outline:
          "border border-outline bg-transparent text-on-surface-variant [a&]:hover:bg-on-surface/8",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "span"

  return (
    <Comp
      data-slot="badge"
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  )
}

export { Badge, badgeVariants }
