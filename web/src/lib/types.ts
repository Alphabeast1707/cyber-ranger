export type Category = "sqli" | "xss" | "cmdi" | "traversal" | "benign";

export interface FeedRow {
  payload: string;
  category: Category;
  endpoint: string;
  origin: string;
  breached: boolean;
  detected: boolean;
  matched_rule: string | null;
  blue_note: string;
  evaded: boolean;
  learned: string | null;
}

export interface Generation {
  type: "generation";
  gen: number;
  generations: number;
  mock_mode: boolean;
  attacks: number;
  breaches: number;
  detected: number;
  evaded: number;
  false_alarms: number;
  red_success_rate: number;
  blue_detection_rate: number;
  blue_rules: number;
  blue_learned: number;
  red_variants: number;
  total_breaches: number;
  feed: FeedRow[];
  series_red: number[];
  series_blue: number[];
}

export interface Summary {
  type: "summary";
  generations: number;
  mock_mode: boolean;
  total_breaches: number;
  blue_rules: number;
  blue_learned: number;
  red_variants: number;
  final_red_success: number;
  final_blue_detection: number;
  series_red: number[];
  series_blue: number[];
}
