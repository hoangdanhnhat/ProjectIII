import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Icon } from "./Icon";
import { ToastContext, type ToastTone } from "./toast-context";

interface Item {
  id: number;
  message: string;
  tone: ToastTone;
}

const TONE_ICON = { info: "info", success: "check-circle", error: "alert" } as const;

/** ToastProvider renders the stack and exposes useToast(). */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Item[]>([]);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    const pending = timers.current;
    return () => pending.forEach((timer) => window.clearTimeout(timer));
  }, []);

  const push = useCallback((message: string, tone: ToastTone = "info") => {
    const id = Date.now() + Math.random();
    setItems((list) => [...list.slice(-2), { id, message, tone }]);
    timers.current.push(
      window.setTimeout(() => setItems((list) => list.filter((item) => item.id !== id)), 4200),
    );
  }, []);

  const value = useMemo(() => push, [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toasts" aria-live="polite">
        {items.map((item) => (
          <div
            key={item.id}
            className="toast"
            data-tone={item.tone === "info" ? undefined : item.tone}
            role="status"
          >
            <Icon name={TONE_ICON[item.tone]} />
            <span>{item.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
