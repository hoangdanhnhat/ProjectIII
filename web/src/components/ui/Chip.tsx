import type { ReactNode } from "react";

export type Tone = "neutral" | "red" | "amber" | "green" | "blue";

interface ChipProps {
  tone?: Tone;
  dot?: boolean;
  title?: string;
  children: ReactNode;
}

/** Chip is a neutral pill with a semantic dot; only risk tones add color. */
export function Chip({ tone = "neutral", dot = true, title, children }: ChipProps) {
  return (
    <span className="chip" data-tone={tone === "neutral" ? undefined : tone} title={title}>
      {dot ? <span className="chip-dot" /> : null}
      {children}
    </span>
  );
}
