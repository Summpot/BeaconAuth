import { cn } from "@/lib/utils"

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn(
        "bg-surface-container-highest animate-pulse rounded-xs",
        className
      )}
      {...props}
    />
  )
}

export { Skeleton }
