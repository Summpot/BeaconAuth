import * as React from "react"

import { cn } from "@/lib/utils"
import { Card, CardContent } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import * as m from "@/paraglide/messages"

type PageLoaderProps = {
  title?: string
  description?: string
  icon?: React.ReactNode
  className?: string
  contentClassName?: string
  compact?: boolean
}

function PageLoader({
  title = m.common_loading(),
  description,
  icon,
  className,
  contentClassName,
  compact = false,
}: PageLoaderProps) {
  const [progress, setProgress] = React.useState(20)

  React.useEffect(() => {
    // A tiny indeterminate progress animation that stops short of 100%.
    // This avoids awkward "0%" while still giving the UI some life.
    const steps = [20, 32, 46, 61, 72, 82, 90, 94]
    let idx = 0

    const t = setInterval(() => {
      idx = (idx + 1) % steps.length
      setProgress(steps[idx] ?? 20)
    }, 550)

    return () => clearInterval(t)
  }, [])

  return (
    <div
      aria-busy="true"
      aria-live="polite"
      className={cn(
        "min-h-full flex items-center justify-center p-4 bg-surface",
        className
      )}
    >
      <Card className="rounded-xl">
        <CardContent className={cn("p-8", contentClassName)}>
          <div className="flex items-start gap-4">
            <div className="relative">
              <div className="relative size-12 rounded-full bg-primary-container text-on-primary-container flex items-center justify-center">
                {icon ?? <Spinner className="size-6" />}
              </div>
            </div>

            <div className="min-w-0 flex-1">
              <div className="text-title-md text-on-surface">{title}</div>
              {description ? (
                <div className="mt-1 text-body-md text-on-surface-variant">
                  {description}
                </div>
              ) : null}

              <div className={cn("mt-4", compact && "mt-3")}>
                <Progress value={progress} />
              </div>

              {compact ? null : (
                <div className="mt-5 space-y-2">
                  <Skeleton className="h-3 w-48" />
                  <Skeleton className="h-3 w-72 max-w-full" />
                  <Skeleton className="h-3 w-56" />
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export { PageLoader }
