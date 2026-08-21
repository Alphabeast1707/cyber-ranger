import { motion } from "framer-motion";
import { Shield, Swords } from "lucide-react";

/** Hero tug-of-war: who currently controls the engagement, Blue vs Red. */
export function DominanceMeter({
  blue, red,
}: { blue: number; red: number }) {
  const total = blue + red;
  const bluePct = total > 0 ? (blue / total) * 100 : 50;
  const redPct = 100 - bluePct;
  const edge = bluePct - 50;
  const leader = Math.abs(edge) < 2 ? "even" : edge > 0 ? "blue" : "red";

  return (
    <div className="rounded-xl border bg-[var(--color-surface)]/80 px-5 py-4 backdrop-blur-sm
      shadow-[0_20px_40px_-24px_rgba(0,0,0,0.9)]">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2 text-[var(--color-blue)]">
          <Shield className="h-4 w-4" strokeWidth={1.9} />
          <span className="text-[13px] font-semibold">Defender</span>
          <span className="tnum text-[13px] text-[var(--color-muted)]">{bluePct.toFixed(0)}%</span>
        </div>
        <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-[var(--color-dim)]">
          <Swords className="h-3.5 w-3.5" strokeWidth={1.9} />
          Engagement control
        </div>
        <div className="flex items-center gap-2 text-[var(--color-red)]">
          <span className="tnum text-[13px] text-[var(--color-muted)]">{redPct.toFixed(0)}%</span>
          <span className="text-[13px] font-semibold">Attacker</span>
          <Swords className="h-4 w-4" strokeWidth={1.9} />
        </div>
      </div>

      <div className="relative h-3 overflow-hidden rounded-full bg-[var(--color-surface-2)] ring-1 ring-inset ring-[var(--color-border)]">
        <motion.div
          className="absolute inset-y-0 left-0"
          style={{ background: "linear-gradient(90deg,#0ea5e9,#38bdf8)", boxShadow: "0 0 20px #38bdf870" }}
          animate={{ width: `${bluePct}%` }}
          transition={{ type: "spring", stiffness: 90, damping: 18 }}
        />
        <motion.div
          className="absolute inset-y-0 right-0"
          style={{ background: "linear-gradient(90deg,#f43f5e,#fb7185)", boxShadow: "0 0 20px #f43f5e70" }}
          animate={{ width: `${redPct}%` }}
          transition={{ type: "spring", stiffness: 90, damping: 18 }}
        />
        {/* center divider */}
        <motion.div
          className="absolute inset-y-0 w-px bg-white/60"
          animate={{ left: `${bluePct}%` }}
          transition={{ type: "spring", stiffness: 90, damping: 18 }}
        />
      </div>

      <div className="mt-2 text-center text-[11px] text-[var(--color-dim)]">
        {leader === "even"
          ? "Stalemate — both sides trading blows"
          : leader === "blue"
            ? "Defender is containing the attacker"
            : "Attacker is breaking through the defense"}
      </div>
    </div>
  );
}
