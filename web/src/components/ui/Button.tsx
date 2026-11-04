import type { ButtonHTMLAttributes } from "react";
import { Icon, type IconName } from "./Icon";

type Variant = "primary" | "secondary" | "ghost";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  small?: boolean;
  block?: boolean;
  icon?: IconName;
  busy?: boolean;
}

export function Button({
  variant = "secondary",
  small = false,
  block = false,
  icon,
  busy = false,
  className,
  children,
  disabled,
  type = "button",
  ...rest
}: ButtonProps) {
  const classes = ["btn"];
  if (variant === "primary") classes.push("btn--primary");
  if (variant === "ghost") classes.push("btn--ghost");
  if (small) classes.push("btn--sm");
  if (block) classes.push("btn--block");
  if (className) classes.push(className);

  return (
    <button {...rest} type={type} className={classes.join(" ")} disabled={disabled ?? busy}>
      {busy ? <Icon name="loader" className="icon spin" /> : icon ? <Icon name={icon} /> : null}
      {children}
    </button>
  );
}
