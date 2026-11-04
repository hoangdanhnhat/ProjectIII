import { useCallback, useEffect, useState } from "react";
import { ApiError, fetchMeta } from "../api/client";
import type { Meta } from "../api/types";

const TOKEN_KEY = "dfir.operator.token";

function readStoredToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

function storeToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Storage can be unavailable; the session still works for this tab.
  }
}

/**
 * useSession owns the operator token and validates it against /v1/meta on
 * load. A rejected token clears the session and surfaces the reason.
 */
export function useSession() {
  const [token, setToken] = useState(readStoredToken);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState("");
  const [restoring, setRestoring] = useState(() => readStoredToken() !== "");

  // Resume a stored session once on mount. State is updated from the
  // promise callbacks, never synchronously in the effect body.
  useEffect(() => {
    const stored = readStoredToken();
    if (!stored) return;
    let cancelled = false;
    fetchMeta(stored)
      .then((info) => {
        if (cancelled) return;
        setMeta(info);
        setError("");
      })
      .catch((failure: unknown) => {
        if (cancelled) return;
        if (failure instanceof ApiError && failure.status === 401) {
          storeToken("");
          setToken("");
          setError("That token was rejected by the server.");
        } else if (failure instanceof ApiError && failure.status !== 0) {
          setError(failure.message);
        } else {
          setError("Cannot reach the server.");
        }
      })
      .finally(() => {
        if (!cancelled) setRestoring(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const connect = useCallback(async (candidate: string) => {
    const info = await fetchMeta(candidate);
    storeToken(candidate);
    setToken(candidate);
    setMeta(info);
    setError("");
  }, []);

  const disconnect = useCallback(() => {
    storeToken("");
    setToken("");
    setMeta(null);
    setError("");
  }, []);

  const clearError = useCallback(() => setError(""), []);

  return {
    token,
    meta,
    error,
    restoring,
    connect,
    disconnect,
    clearError,
  };
}
