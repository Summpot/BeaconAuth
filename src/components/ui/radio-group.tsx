"use client"

import * as React from "react"
import * as RadioGroupPrimitive from "@radix-ui/react-radio-group"
import { CircleIcon } from "lucide-react"

import { cn } from "@/lib/utils"

function RadioGroup({
  className,
  ...props
}: React.ComponentProps<typeof RadioGroupPrimitive.Root>) {
  return (
    <RadioGroupPrimitive.Root
      data-slot="radio-group"
      className={cn("grid gap-3", className)}
      {...props}
    />
  )
}

function RadioGroupItem({
  className,
  ...props
}: React.ComponentProps<typeof RadioGroupPrimitive.Item>) {
  return (
    <RadioGroupPrimitive.Item
      data-slot="radio-group-item"
      className={cn(
        // M3 radio button: 20dp target inside a 40dp state-layer hit area.
        "relative aspect-square size-5 shrink-0 rounded-full border-2 border-on-surface-variant bg-transparent text-primary outline-none transition-colors duration-200 ease-standard",
        // 40dp state layer, drawn outside the 20dp control per the M3 spec.
        "before:absolute before:-inset-2.5 before:rounded-full before:bg-current before:opacity-0 before:transition-opacity before:duration-200 before:content-['']",
        "hover:before:opacity-8 focus-visible:before:opacity-10 active:before:opacity-10",
        "data-[state=checked]:border-primary",
        "aria-invalid:border-error aria-invalid:text-error",
        "focus-visible:outline-3 focus-visible:outline-offset-4 focus-visible:outline-primary",
        "disabled:cursor-not-allowed disabled:border-on-surface/38 disabled:text-on-surface/38",
        className
      )}
      {...props}
    >
      <RadioGroupPrimitive.Indicator
        data-slot="radio-group-indicator"
        className="relative flex size-full items-center justify-center"
      >
        <CircleIcon className="absolute top-1/2 left-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 fill-current stroke-none" />
      </RadioGroupPrimitive.Indicator>
    </RadioGroupPrimitive.Item>
  )
}

export { RadioGroup, RadioGroupItem }
