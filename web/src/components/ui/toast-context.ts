import { createContext, useContext } from "react";

export type ToastTone = "info" | "success" | "error";

export type PushToast = (message: string, tone?: ToastTone) => void;

export const ToastContext = createContext<PushToast>(() => {});

/** useToast returns the push function from the nearest ToastProvider. */
export function useToast(): PushToast {
  return useContext(ToastContext);
}
