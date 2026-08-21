import { AnimatePresence, motion } from "framer-motion";
import { ShieldCheck, ShieldOff, Bug, CheckCircle2 } from "lucide-react";
import type { FeedRow } from "@/lib/types";
import { cn } from "@/lib/utils";

type Row = FeedRow & { gen: number; id: number };

const CAT: Record<string, { label: string; cls: string }> = {
  sqli: { label: "SQLi", cls: "text-[#fb7185] bg-[#f43f5e]/10 border-[#f43f5e]/25" },
  xss: { label: "XSS", cls: "text-[#c4b5fd] bg-[#8b5cf6]/10 border-[#8b5cf6]/25" },
  cmdi: { label: "CMDi", cls: "text-[#fdba74] bg-[#f97316]/10 border-[#f97316]/25" },
  traversal: { label: "PATH", cls: "text-[#5eead4] bg-[#14b8a6]/10 border-[#14b8a6]/25" },
  benign: { label: "BENIGN", cls: "text-[var(--color-dim)] bg-white/5 border-[var(--color-border)]" },
};

function Verdict({ r }: { r: Row }) {
  if (r.category === "benign") {
    return r.detected
      ? <span className="text-[var(--color-warn)]">False positive</span>
      : <span className="inline-flex items-center gap-1 text-[var(--color-good)]"><CheckCircle2 className="h-3.5 w-3.5" />Clean</span>;
  }
  if (r.evaded) return <span className="inline-flex items-center gap-1 text-[var(--color-red)] font-medium"><ShieldOff className="h-3.5 w-3.5" />Evaded</span>;
  if (r.detected) return <span className="inline-flex items-center gap-1 text-[var(--color-blue)] font-medium"><ShieldCheck className="h-3.5 w-3.5" />Blocked</span>;
  return <span className="text-[var(--color-dim)]">Failed</span>;
}

export function AttackFeed({ rows }: { rows: Row[] }) {
  return (
    <div className="max-h-[430px] overflow-y-auto pr-1">
      <div className="grid grid-cols-[36px_1fr_74px_96px] gap-3 px-1 pb-2 text-[10px] uppercase tracking-[0.14em] text-[var(--color-dim)]">
        <span>Gen</span><span>Payload</span><span>Type</span><span>Verdict</span>
      </div>
      <AnimatePresence initial={false}>
        {rows.map((r) => {
          const cat = CAT[r.category] ?? CAT.benign;
          return (
            <motion.div
              key={r.id}
              layout
              initial={{ opacity: 0, y: -8, backgroundColor: "rgba(56,189,248,0.10)" }}
              animate={{ opacity: 1, y: 0, backgroundColor: "rgba(0,0,0,0)" }}
              transition={{ duration: 0.5 }}
              className="grid grid-cols-[36px_1fr_74px_96px] items-center gap-3 rounded-md border-b border-[var(--color-border-soft)] px-1 py-2 text-[12px]"
            >
              <span className="tnum text-[var(--color-dim)]">{r.gen}</span>
              <div className="min-w-0">
                <code className="block truncate font-mono text-[12px] text-[#cdd2df]">{r.payload}</code>
                {r.learned && (
                  <span className="mt-0.5 inline-flex items-center gap-1 text-[10px] text-[var(--color-blue)]">
                    <Bug className="h-3 w-3" />signature learned
                  </span>
                )}
              </div>
              <span className={cn("justify-self-start rounded-md border px-1.5 py-0.5 text-[10px] font-semibold tracking-wide", cat.cls)}>
                {cat.label}
              </span>
              <span className="text-[12px]"><Verdict r={r} /></span>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
