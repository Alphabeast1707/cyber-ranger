import * as React from "react";
import { cn } from "@/lib/utils";

interface TabsCtx { value: string; setValue: (v: string) => void; }
const Ctx = React.createContext<TabsCtx | null>(null);

export function Tabs({
  value, onValueChange, children, className,
}: { value: string; onValueChange: (v: string) => void; children: React.ReactNode; className?: string }) {
  return <div className={className}><Ctx.Provider value={{ value, setValue: onValueChange }}>{children}</Ctx.Provider></div>;
}

export function TabsList({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn(
      "inline-flex items-center gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-1",
      className)} {...props} />
  );
}

export function TabsTrigger({
  value, children, accent,
}: { value: string; children: React.ReactNode; accent?: string }) {
  const ctx = React.useContext(Ctx)!;
  const active = ctx.value === value;
  return (
    <button
      onClick={() => ctx.setValue(value)}
      className={cn(
        "relative rounded-md px-3 py-1.5 text-[12px] font-medium transition-colors",
        active ? "text-[var(--color-fg)]" : "text-[var(--color-dim)] hover:text-[var(--color-muted)]",
      )}
      style={active ? { background: "var(--color-surface)", boxShadow: "0 1px 0 rgba(255,255,255,0.04) inset" } : undefined}
    >
      <span className="inline-flex items-center gap-1.5">
        {accent && <span className="h-1.5 w-1.5 rounded-full" style={{ background: active ? accent : "var(--color-dim)" }} />}
        {children}
      </span>
    </button>
  );
}

export function TabsContent({
  value, children,
}: { value: string; children: React.ReactNode }) {
  const ctx = React.useContext(Ctx)!;
  if (ctx.value !== value) return null;
  return <div>{children}</div>;
}
