import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badge = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium tracking-wide",
  {
    variants: {
      variant: {
        neutral: "border-[var(--color-border)] bg-[var(--color-surface-2)] text-[var(--color-muted)]",
        live: "border-[var(--color-good)]/30 bg-[var(--color-good)]/10 text-[var(--color-good)]",
        mock: "border-[var(--color-warn)]/30 bg-[var(--color-warn)]/10 text-[var(--color-warn)]",
        red: "border-[var(--color-red)]/30 bg-[var(--color-red)]/10 text-[var(--color-red)]",
        blue: "border-[var(--color-blue)]/30 bg-[var(--color-blue)]/10 text-[var(--color-blue)]",
      },
    },
    defaultVariants: { variant: "neutral" },
  },
);

export function Badge({
  className, variant, ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badge>) {
  return <span className={cn(badge({ variant }), className)} {...props} />;
}
