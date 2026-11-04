import type { ReactNode } from "react";

/** Tag labels a category (IP, domain, artifact kind) without implying tone. */
export function Tag({ children }: { children: ReactNode }) {
  return <span className="tag">{children}</span>;
}
