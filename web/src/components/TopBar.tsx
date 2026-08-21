import { motion } from "framer-motion";
import { Radar } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { Status } from "@/hooks/useArena";

function StatusBadge({ status }: { status: Status }) {
  if (status === "live")
    return <Badge variant="live"><span className="h-1.5 w-1.5 rounded-full bg-[var(--color-good)] animate-pulse" />LIVE · DVWA</Badge>;
  if (status === "mock")
    return <Badge variant="mock"><span className="h-1.5 w-1.5 rounded-full bg-[var(--color-warn)]" />SANDBOX · SIMULATED</Badge>;
  if (status === "done")
    return <Badge variant="neutral">SESSION COMPLETE</Badge>;
  return <Badge variant="neutral"><span className="h-1.5 w-1.5 rounded-full bg-[var(--color-dim)] animate-pulse" />CONNECTING</Badge>;
}

export function TopBar({ status, gen, total }: { status: Status; gen: number; total: number }) {
  const pct = total ? (gen / total) * 100 : 0;
  return (
    <header className="flex items-center justify-between">
      <div className="flex items-center gap-3.5">
        <div className="relative grid h-10 w-10 place-items-center rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
          <Radar className="h-5 w-5 text-[var(--color-fg)]" strokeWidth={1.8} />
          <span className="absolute inset-0 rounded-xl"
            style={{ boxShadow: "inset 0 0 22px rgba(56,189,248,0.18)" }} />
        </div>
        <div>
          <div className="flex items-baseline gap-2">
            <h1 className="text-[17px] font-semibold tracking-tight">CyberRanger</h1>
            <span className="text-[12px] font-medium text-[var(--color-dim)]">Arena</span>
          </div>
          <p className="text-[11.5px] leading-tight text-[var(--color-muted)]">
            Adversarial co-evolution engine · red team vs blue team
          </p>
        </div>
      </div>

      <div className="flex items-center gap-5">
        <div className="hidden items-center gap-3 sm:flex">
          <span className="text-[11px] uppercase tracking-[0.14em] text-[var(--color-dim)]">Generation</span>
          <span className="tnum text-[15px] font-semibold">
            {String(gen).padStart(2, "0")}<span className="text-[var(--color-dim)]"> / {String(total || 0).padStart(2, "0")}</span>
          </span>
          <div className="h-1.5 w-28 overflow-hidden rounded-full bg-[var(--color-surface-2)]">
            <motion.div className="h-full rounded-full"
              style={{ background: "linear-gradient(90deg,#38bdf8,#818cf8)" }}
              animate={{ width: `${pct}%` }} transition={{ type: "spring", stiffness: 80, damping: 18 }} />
          </div>
        </div>
        <StatusBadge status={status} />
      </div>
    </header>
  );
}
