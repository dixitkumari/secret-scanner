export type Severity =
  | "Critical"
  | "High"
  | "Medium"
  | "Low";

export type Finding = {
  id: number;
  type: string;
  file: string;
  line: number;
  commit: string;
  author: string;
  date: string;
  classification: string;
  severity: Severity;
  confidence: number | null;
  reason: string;
  recommendedAction: string;
};

/*
 * The dashboard starts empty because findings now come from
 * the real Python scanner.
 *
 * This array is kept so the existing Finding type and imports
 * remain simple.
 */
export const findings: Finding[] = [];