import { useToast } from "./toast-context";
import { Icon } from "./Icon";

interface CopyButtonProps {
  value: string;
  label: string;
}

export function CopyButton({ value, label }: CopyButtonProps) {
  const toast = useToast();

  async function copy() {
    try {
      if (!navigator.clipboard) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(value);
      toast(`Copied ${label}`, "success");
    } catch {
      toast("Clipboard unavailable; select and copy manually.", "error");
    }
  }

  return (
    <button
      type="button"
      className="icon-btn"
      onClick={copy}
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
    >
      <Icon name="copy" />
    </button>
  );
}
