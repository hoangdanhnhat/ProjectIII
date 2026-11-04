export type IconName =
  | "sun"
  | "moon"
  | "x"
  | "plus"
  | "refresh"
  | "search"
  | "download"
  | "copy"
  | "loader"
  | "external"
  | "trash"
  | "ban"
  | "check"
  | "check-circle"
  | "alert"
  | "info"
  | "globe"
  | "network"
  | "server"
  | "layers"
  | "activity"
  | "inbox"
  | "folder"
  | "chevron-right"
  | "key";

interface IconProps {
  name: IconName;
  className?: string;
}

/** Icon renders one symbol from the sprite embedded in index.html. */
export function Icon({ name, className = "icon" }: IconProps) {
  return (
    <svg className={className} aria-hidden="true" focusable="false">
      <use href={`#i-${name}`} />
    </svg>
  );
}
