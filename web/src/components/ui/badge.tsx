import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors",
  {
    variants: {
      variant: {
        // Смысловые цвета статусов (enrolled/pending/blocked/active) не меняются.
        // В тёмной теме фон — полупрозрачный тинт того же цвета, а не плотный -900:
        // плотный блок гасил стекло под собой; тонкая рамка держит форму бейджа.
        default:     "border-blue-500/20 bg-blue-500/15 text-blue-700 dark:border-blue-400/25 dark:bg-blue-400/15 dark:text-blue-300",
        secondary:   "border-amber-500/20 bg-amber-500/15 text-amber-800 dark:border-amber-400/25 dark:bg-amber-400/15 dark:text-amber-300",
        destructive: "border-red-500/20 bg-red-500/15 text-red-700 dark:border-red-400/25 dark:bg-red-400/15 dark:text-red-300",
        outline:     "border-border text-muted-foreground",
        success:     "border-emerald-500/20 bg-emerald-500/15 text-emerald-700 dark:border-emerald-400/25 dark:bg-emerald-400/15 dark:text-emerald-300",
      },
    },
    defaultVariants: { variant: "default" },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
