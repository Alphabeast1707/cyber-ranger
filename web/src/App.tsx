import { Activity, ShieldCheck, Swords, Bug, GitBranch } from "lucide-react";
import { Toaster } from "sonner";
import { useArena } from "@/hooks/useArena";
import { TopBar } from "@/components/TopBar";
import { DominanceMeter } from "@/components/DominanceMeter";
import { StatCard } from "@/components/StatCard";
import { ArmsRaceChart } from "@/components/ArmsRaceChart";
import { AttackFeed } from "@/components/AttackFeed";
import { RedConsole, BlueConsole } from "@/components/Consoles";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";

export default function App() {
  const { gen, feed, summary, status, chartData } = useArena();
  const [tab, setTab] = useState("combat");

  const g = gen;
  const blueDetect = g?.blue_detection_rate ?? 0;
  const redEvade = g?.red_success_rate ?? 0;

  return (
    <div className="relative z-10 mx-auto max-w-[1360px] px-6 py-6">
      <Toaster theme="dark" position="bottom-right" toastOptions={{
        style: {
          background: "var(--color-surface-2)", border: "1px solid var(--color-border)",
          color: "var(--color-fg)", fontFamily: "var(--font-sans)",
        },
      }} />

      <TopBar status={status} gen={g?.gen ?? 0} total={g?.generations ?? 0} />

      <div className="mt-6">
        <DominanceMeter blue={blueDetect} red={redEvade} />
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Blue detection" value={blueDetect} decimals={0} suffix="%"
          sub={g ? `${g.detected} of ${g.attacks} intercepted` : "awaiting stream"}
          icon={ShieldCheck} accent="blue" />
        <StatCard label="Red evasion" value={redEvade} decimals={0} suffix="%"
          sub={g ? `${g.evaded} breached undetected` : "awaiting stream"}
          icon={Swords} accent="red" />
        <StatCard label="Total breaches" value={g?.total_breaches ?? 0}
          sub="successful exploits" icon={Bug} accent="neutral" />
        <StatCard label="Rules learned" value={g?.blue_learned ?? 0}
          sub={g ? `${g.red_variants} red variants bred` : "adaptive defense"} icon={GitBranch} accent="neutral" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1.5fr_1fr]">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>Arms race</CardTitle>
              <p className="mt-0.5 text-[11.5px] text-[var(--color-dim)]">
                Evasion vs detection across generations
              </p>
            </div>
            <div className="flex items-center gap-4 text-[11px]">
              <span className="flex items-center gap-1.5 text-[var(--color-blue)]">
                <span className="h-2 w-2 rounded-full bg-[var(--color-blue)]" />Detection</span>
              <span className="flex items-center gap-1.5 text-[var(--color-red)]">
                <span className="h-2 w-2 rounded-full bg-[var(--color-red)]" />Evasion</span>
            </div>
          </CardHeader>
          <CardContent>
            <ArmsRaceChart data={chartData} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-[var(--color-dim)]" strokeWidth={1.75} />
              <CardTitle>Engagement log</CardTitle>
            </div>
            <Tabs value={tab} onValueChange={setTab}>
              <TabsList>
                <TabsTrigger value="combat">Combat</TabsTrigger>
                <TabsTrigger value="red" accent="var(--color-red)">Red</TabsTrigger>
                <TabsTrigger value="blue" accent="var(--color-blue)">Blue</TabsTrigger>
              </TabsList>
            </Tabs>
          </CardHeader>
          <CardContent>
            <p className="-mt-1 mb-3 text-[11.5px] text-[var(--color-dim)]">
              {tab === "combat" && "Every payload, breach, and verdict as it lands."}
              {tab === "red" && "Attacker\u2019s view \u2014 technique, target, and how each variant was bred."}
              {tab === "blue" && "Defender\u2019s view \u2014 the rule matched, or the signature just learned."}
            </p>
            <Tabs value={tab} onValueChange={setTab}>
              <TabsContent value="combat"><AttackFeed rows={feed} /></TabsContent>
              <TabsContent value="red"><RedConsole rows={feed} /></TabsContent>
              <TabsContent value="blue"><BlueConsole rows={feed} /></TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>

      <AnimatePresence>
        {summary && (
          <motion.div
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface)]/60 px-5 py-3.5 text-[12.5px]">
            <span className="text-[var(--color-muted)]">
              Session complete · <span className="tnum text-[var(--color-fg)]">{summary.generations}</span> generations ·
              <span className="tnum text-[var(--color-fg)]"> {summary.total_breaches}</span> breaches ·
              Blue learned <span className="tnum text-[var(--color-blue)]">{summary.blue_learned}</span> rules ·
              Red bred <span className="tnum text-[var(--color-red)]">{summary.red_variants}</span> variants
            </span>
            <span className="font-medium" style={{
              color: summary.final_red_success > summary.final_blue_detection ? "var(--color-red)" : "var(--color-blue)",
            }}>
              {summary.final_red_success > summary.final_blue_detection
                ? "Attacker out-evolved the static defender"
                : "Defender held the line"}
              <span className="ml-2 font-normal text-[var(--color-dim)]">— next: LLM reasoning + RL retraining</span>
            </span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
