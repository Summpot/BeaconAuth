import { cn } from "@/lib/utils"
import { motion } from "@/lib/motion"
import * as m from "@/paraglide/messages"
import { BeaconIcon } from "@/components/beacon-icon"

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
  return (
    <div
      aria-busy="true"
      aria-live="polite"
      className={cn(
        "relative flex flex-col items-center justify-center overflow-hidden bg-background",
        compact
          ? "min-h-[220px] px-6 py-10"
          : "min-h-[min(56vh,520px)] px-6 py-16 sm:py-20",
        className
      )}
    >
      {/* Ambient glow — matches hero / Scandi airy background */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 overflow-hidden"
      >
        <div className="absolute left-1/2 top-[38%] h-[420px] w-[760px] max-w-[92vw] -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary/[0.035] blur-3xl dark:bg-primary/[0.06]" />
        <div className="absolute left-1/2 top-[42%] h-[320px] w-[520px] max-w-[88vw] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/40 blur-3xl opacity-60 dark:bg-accent/15 dark:opacity-100" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.42, ease: "easeOut" }}
        className={cn(
          "relative z-10 flex w-full max-w-sm flex-col items-center text-center",
          contentClassName
        )}
      >
        {/* Beacon halo */}
        <div className="relative flex size-20 items-center justify-center">
          {/* Outer breathing ring */}
          <motion.div
            aria-hidden="true"
            className="absolute size-[84px] rounded-full border border-primary/[0.09] dark:border-white/10"
            animate={{ scale: [1, 1.08, 1], opacity: [0.9, 0.45, 0.9] }}
            transition={{
              duration: 2.6,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
          {/* Inner soft fill ring */}
          <motion.div
            aria-hidden="true"
            className="absolute size-[68px] rounded-full border border-primary/[0.07] bg-primary/[0.03] dark:border-white/[0.07] dark:bg-white/[0.04]"
            animate={{ scale: [1, 1.06, 1], opacity: [0.85, 0.5, 0.85] }}
            transition={{
              duration: 2.6,
              repeat: Infinity,
              ease: "easeInOut",
              delay: 0.2,
            }}
          />
          {/* Icon card */}
          <div className="relative flex size-14 items-center justify-center rounded-2xl border border-border/70 bg-card/90 shadow-sm shadow-primary/[0.04] backdrop-blur supports-backdrop-filter:bg-card/80">
            {icon ?? <BeaconIcon className="size-7 text-primary" />}
            {/* Subtle top highlight */}
            <span
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-[9px] top-[1px] h-px bg-gradient-to-r from-transparent via-white/70 to-transparent opacity-70 dark:via-white/20"
            />
          </div>
        </div>

        <div className={cn("flex flex-col items-center", compact ? "mt-5 gap-1" : "mt-6 gap-1.5")}>
          <h2 className="text-balance text-[15px] font-semibold leading-none tracking-tight text-foreground">
            {title}
          </h2>
          {description ? (
            <p className="max-w-[28ch] text-balance text-sm leading-relaxed text-muted-foreground">
              {description}
            </p>
          ) : null}
        </div>

        {/* Shimmer rail — indeterminate, no fake percentages */}
        <div
          className={cn(
            "relative overflow-hidden rounded-full bg-border/70 dark:bg-border/60",
            compact ? "mt-6 h-1 w-24" : "mt-7 h-1 w-28 sm:w-32"
          )}
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <motion.div
            className="absolute inset-y-0 left-0 w-[56%] rounded-full bg-gradient-to-r from-transparent via-primary to-transparent opacity-80 dark:via-primary/90"
            style={{ filter: "blur(0.2px)" }}
            animate={{ x: ["-100%", "180%"] }}
            transition={{
              duration: 1.15,
              repeat: Infinity,
              ease: "easeInOut",
              repeatDelay: 0.15,
            }}
          />
          {/* Second shimmer for depth, slightly delayed */}
          <motion.div
            className="absolute inset-y-0 left-0 w-[42%] rounded-full bg-gradient-to-r from-transparent via-primary/50 to-transparent dark:via-primary/40"
            animate={{ x: ["-100%", "220%"] }}
            transition={{
              duration: 1.35,
              repeat: Infinity,
              ease: "easeInOut",
              delay: 0.18,
            }}
          />
        </div>

        {/* Ternary dots — very subtle life */}
        <div
          aria-hidden="true"
          className={cn(
            "flex items-center gap-1.5",
            compact ? "mt-4" : "mt-5"
          )}
        >
          {[0, 1, 2].map((i) => (
            <motion.span
              key={i}
              className="size-1 rounded-full bg-primary/30 dark:bg-primary/40"
              animate={{ opacity: [0.35, 1, 0.35], scale: [0.85, 1, 0.85] }}
              transition={{
                duration: 1.4,
                repeat: Infinity,
                ease: "easeInOut",
                delay: i * 0.18,
              }}
            />
          ))}
        </div>
      </motion.div>
    </div>
  )
}

export { PageLoader }
