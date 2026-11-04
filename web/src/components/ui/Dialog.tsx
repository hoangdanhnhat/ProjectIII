import { useEffect, useRef, type ReactNode } from "react";
import { Icon } from "./Icon";

interface DialogProps {
  open: boolean;
  onClose: () => void;
  labelledBy: string;
  children: ReactNode;
}

/**
 * Dialog wraps the native modal <dialog>: ESC, focus containment and the
 * backdrop come from the platform, with controlled open/close semantics.
 */
export function Dialog({ open, onClose, labelledBy, children }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    if (open && !node.open) node.showModal();
    else if (!open && node.open) node.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      className="dialog"
      aria-labelledby={labelledBy}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === ref.current) onClose();
      }}
    >
      {children}
    </dialog>
  );
}

interface DialogHeadProps {
  eyebrow?: string;
  title: string;
  id: string;
  onClose: () => void;
}

export function DialogHead({ eyebrow, title, id, onClose }: DialogHeadProps) {
  return (
    <header className="dialog-head">
      <div>
        {eyebrow ? <div className="eyebrow">{eyebrow}</div> : null}
        <h2 id={id}>{title}</h2>
      </div>
      <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
        <Icon name="x" />
      </button>
    </header>
  );
}
