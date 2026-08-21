import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import type { FeedRow, Generation, Summary } from "@/lib/types";

export type Status = "connecting" | "live" | "mock" | "done";

const CAT_LABEL: Record<string, string> = {
  sqli: "SQL injection", xss: "Cross-site scripting",
  cmdi: "Command injection", traversal: "Path traversal", benign: "Benign",
};

/** Connects to the FastAPI SSE stream and exposes live arena state. */
export function useArena() {
  const [gen, setGen] = useState<Generation | null>(null);
  const [feed, setFeed] = useState<(FeedRow & { gen: number; id: number })[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [status, setStatus] = useState<Status>("connecting");
  const idRef = useRef(0);

  useEffect(() => {
    const es = new EventSource("/stream");

    es.onmessage = (ev) => {
      const d = JSON.parse(ev.data) as Generation | Summary | { type: "done" };

      if (d.type === "generation") {
        setStatus(d.mock_mode ? "mock" : "live");
        setGen(d);
        setFeed((prev) => {
          const rows = d.feed.map((r) => ({ ...r, gen: d.gen, id: idRef.current++ }));
          return [...rows.reverse(), ...prev].slice(0, 80);
        });
        // Fire a toast on newly-learned Blue rules this generation.
        d.feed.forEach((r) => {
          if (r.learned) {
            toast(`Blue learned a detection rule`, {
              description: `${CAT_LABEL[r.category] ?? r.category} · signature captured`,
            });
          }
        });
      } else if (d.type === "summary") {
        setSummary(d);
      } else {
        setStatus("done");
        es.close();
      }
    };

    es.onerror = () => setStatus((s) => (s === "connecting" ? "connecting" : s));
    return () => es.close();
  }, []);

  const chartData =
    gen?.series_red.map((r, i) => ({
      gen: i + 1,
      red: r,
      blue: gen.series_blue[i] ?? 0,
    })) ?? [];

  return { gen, feed, summary, status, chartData };
}
