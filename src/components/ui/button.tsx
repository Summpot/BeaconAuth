import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * Material Design 3 common buttons.
 *
 * The five M3 variants are exposed under their spec names (`filled`,
 * `elevated`, `tonal`, `outlined`, `text`); the shadcn/ui names are kept as
 * aliases so existing call sites keep working:
 *   default -> filled | secondary -> filled tonal | outline -> outlined
 *   ghost   -> text   | link      -> text + underline
 */
const buttonVariants = cva(
  [
    "state-layer relative inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-full",
    "text-label-lg select-none",
    "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-[1.125rem]",
    "outline-none focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-primary",
    "disabled:pointer-events-none disabled:border-transparent disabled:bg-on-surface/12 disabled:text-on-surface/38 disabled:shadow-level0",
    "aria-disabled:pointer-events-none aria-disabled:bg-on-surface/12 aria-disabled:text-on-surface/38",
  ],
  {
    variants: {
      variant: {
        filled: "bg-primary text-on-primary shadow-level0 hover:shadow-level1",
        default: "bg-primary text-on-primary shadow-level0 hover:shadow-level1",
        elevated:
          "bg-surface-container-low text-primary shadow-level1 hover:shadow-level2",
        tonal:
          "bg-secondary-container text-on-secondary-container shadow-level0 hover:shadow-level1",
        secondary:
          "bg-secondary-container text-on-secondary-container shadow-level0 hover:shadow-level1",
        outlined:
          "border border-outline bg-transparent text-primary focus-visible:border-primary disabled:border-on-surface/12",
        outline:
          "border border-outline bg-transparent text-primary focus-visible:border-primary disabled:border-on-surface/12",
        text: "bg-transparent text-primary",
        ghost: "bg-transparent text-on-surface-variant",
        link: "bg-transparent text-primary underline-offset-4 hover:underline",
        destructive: "bg-error text-on-error shadow-level0 hover:shadow-level1",
        "destructive-text": "bg-transparent text-error",
      },
      size: {
        default: "h-10 px-6 has-[>svg:first-child]:pr-6 has-[>svg:first-child]:pl-4",
        sm: "h-8 px-4 text-label-md has-[>svg:first-child]:pr-4 has-[>svg:first-child]:pl-3",
        lg: "h-14 px-8 text-title-md has-[>svg:first-child]:pr-8 has-[>svg:first-child]:pl-6 [&_svg:not([class*='size-'])]:size-6",
        icon: "size-10 p-0",
        "icon-sm": "size-8 p-0",
        "icon-lg": "size-12 p-0 [&_svg:not([class*='size-'])]:size-6",
      },
    },
    compoundVariants: [
      // Text buttons use tighter padding per the M3 spec.
      { variant: "text", size: "default", class: "px-3" },
      { variant: "ghost", size: "default", class: "px-3" },
      { variant: "link", size: "default", class: "px-2" },
      { variant: "text", size: "sm", class: "px-3" },
      { variant: "ghost", size: "sm", class: "px-3" },
      { variant: "destructive-text", size: "default", class: "px-3" },
    ],
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot : "button"

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
