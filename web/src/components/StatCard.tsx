import type { LucideIcon } from "lucide-react";
import { Card } from "@/components/ui/card";
import { AnimatedNumber } from "./AnimatedNumber";
import { cn } from "@/lib/utils";

interface Props {
  label: string;
  value: number;
  suffix?: string;
  decimals?: number;
  sub?: string;
  icon: LucideIcon;
  accent?: "red" | "blue" | "neutral";
}

const ACCENT = {
  red: "var(--color-red)",
  blue: "var(--color-blue)",
  neutral: "var(--color-fg)",
};

export function StatCard({ label, value, suffix, decimals, sub, icon: Icon, accent = "neutral" }: Props) {
  const color = ACCENT[accent];
  return (
    <Card className="overflow-hidden">
      {accent !== "neutral" && (
        <span className="absolute left-0 top-4 bottom-4 w-[3px] rounded-full"
          style={{ background: color, boxShadow: `0 0 16px ${color}` }} />
      )}
      <div className="flex items-start justify-between px-5 pt-4">
        <span className="text-[11px] uppercase tracking-[0.14em] text-[var(--color-dim)]">{label}</span>
        <Icon className="h-4 w-4" style={{ color: accent === "neutral" ? "var(--color-dim)" : color }} strokeWidth={1.75} />
      </div>
      <div className={cn("px-5 pb-4 pt-1")}>
        <div className="tnum text-[34px] font-semibold leading-none tracking-tight"
          style={{ color, textShadow: accent !== "neutral" ? `0 0 24px ${color}40` : "none" }}>
          <AnimatedNumber value={value} decimals={decimals} suffix={suffix} />
        </div>
        {sub && <div className="mt-1.5 text-[12px] text-[var(--color-dim)]">{sub}</div>}
      </div>
    </Card>
  );
}
