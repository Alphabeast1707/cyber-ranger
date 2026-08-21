import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, ShieldCheck, ShieldOff, Crosshair, Search, GitBranch } from "lucide-react";
import type { FeedRow } from "@/lib/types";

type Row = FeedRow & { gen: number; id: number };

const CAT_LABEL: Record<string, string> = {
  sqli: "SQL injection", xss: "Reflected XSS",
  cmdi: "Command injection", traversal: "Path traversal", benign: "Benign request",
};

const rowMotion = {
  initial: { opacity: 0, y: -6 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.45 },
};

/** Attacker's-eye view: technique, target endpoint, payload, outcome. */
export function RedConsole({ rows }: { rows: Row[] }) {
  const attacks = rows.filter((r) => r.category !== "benign");
  return (
    <div className="max-h-[430px] space-y-1.5 overflow-y-auto pr-1 font-mono text-[12px]">
      <AnimatePresence initial={false}>
        {attacks.map((r) => (
          <motion.div key={r.id} layout {...rowMotion}
            className="rounded-md border-l-2 border-[var(--color-red)]/50 bg-[var(--color-red)]/[0.04] px-3 py-2">
            <div className="flex items-center gap-2 text-[11px]">
              <Crosshair className="h-3.5 w-3.5 text-[var(--color-red)]" />
              <span className="tnum text-[var(--color-dim)]">gen {String(r.gen).padStart(2, "0")}</span>
              <span className="font-sans font-medium text-[var(--color-fg)]">{CAT_LABEL[r.category]}</span>
              <ArrowRight className="h-3 w-3 text-[var(--color-dim)]" />
              <span className="text-[var(--color-muted)]">{r.endpoint}</span>
              <span className="ml-auto inline-flex items-center gap-1 font-sans text-[11px] text-[var(--color-blue)]">
                <GitBranch className="h-3 w-3" />{r.origin}
              </span>
            </div>
            <div className="mt-1.5 truncate text-[#e4b8c2]">{r.payload}</div>
            <div className="mt-1 text-[11px]">
              {r.evaded ? (
                <span className="text-[var(--color-red)]">breach landed · undetected — this variant survives to mutate</span>
              ) : r.detected ? (
                <span className="text-[var(--color-dim)]">blocked by defender · Red must find a new angle</span>
              ) : (
                <span className="text-[var(--color-dim)]">payload failed to breach</span>
              )}
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

/** Defender's-eye view: inspection decision + rule reasoning. */
export function BlueConsole({ rows }: { rows: Row[] }) {
  return (
    <div className="max-h-[430px] space-y-1.5 overflow-y-auto pr-1 font-mono text-[12px]">
      <AnimatePresence initial={false}>
        {rows.map((r) => {
          const flagged = r.detected;
          return (
            <motion.div key={r.id} layout {...rowMotion}
              className="rounded-md border-l-2 bg-[var(--color-blue)]/[0.035] px-3 py-2"
              style={{ borderColor: flagged ? "var(--color-blue)" : "var(--color-border)" }}>
              <div className="flex items-center gap-2 text-[11px]">
                <Search className="h-3.5 w-3.5 text-[var(--color-blue)]" />
                <span className="tnum text-[var(--color-dim)]">gen {String(r.gen).padStart(2, "0")}</span>
                <span className="ml-auto inline-flex items-center gap-1 font-sans font-medium">
                  {flagged
                    ? <span className="inline-flex items-center gap-1 text-[var(--color-blue)]"><ShieldCheck className="h-3.5 w-3.5" />FLAGGED</span>
                    : <span className="inline-flex items-center gap-1 text-[var(--color-dim)]"><ShieldOff className="h-3.5 w-3.5" />ALLOWED</span>}
                </span>
              </div>
              <div className="mt-1.5 truncate text-[#b9c6d6]">{r.payload}</div>
              <div className="mt-1 text-[11px]" style={{
                color: r.learned ? "var(--color-blue)" : flagged ? "var(--color-muted)" : "var(--color-dim)",
              }}>
                {r.blue_note}
              </div>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
