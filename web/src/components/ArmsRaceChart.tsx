import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";

interface Point { gen: number; red: number; blue: number; }

function ChartTip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border bg-[var(--color-surface-2)] px-3 py-2 text-[12px] shadow-xl">
      <div className="mb-1 text-[var(--color-dim)]">Generation {label}</div>
      <div className="flex items-center gap-2 text-[var(--color-blue)]">
        <span className="tnum font-medium">{payload.find((p: any) => p.dataKey === "blue")?.value ?? 0}%</span> detection
      </div>
      <div className="flex items-center gap-2 text-[var(--color-red)]">
        <span className="tnum font-medium">{payload.find((p: any) => p.dataKey === "red")?.value ?? 0}%</span> evasion
      </div>
    </div>
  );
}

export function ArmsRaceChart({ data }: { data: Point[] }) {
  return (
    <ResponsiveContainer width="100%" height={288}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="gRed" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#f43f5e" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gBlue" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1e1e26" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="gen" stroke="#64646f" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis domain={[0, 100]} stroke="#64646f" tick={{ fontSize: 11 }} tickLine={false} axisLine={false}
          tickFormatter={(v) => `${v}%`} width={44} />
        <Tooltip content={<ChartTip />} cursor={{ stroke: "#2a2a33" }} />
        <Area type="monotone" dataKey="blue" stroke="#38bdf8" strokeWidth={2.4}
          fill="url(#gBlue)" dot={false} isAnimationActive animationDuration={500} />
        <Area type="monotone" dataKey="red" stroke="#f43f5e" strokeWidth={2.4}
          fill="url(#gRed)" dot={false} isAnimationActive animationDuration={500} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
