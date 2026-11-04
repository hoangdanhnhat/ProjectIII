/** Skeleton is a neutral shimmer placeholder for loading rows. */
export function Skeleton({ className }: { className?: string }) {
  return <div className={className ? `skeleton ${className}` : "skeleton"} aria-hidden="true" />;
}
