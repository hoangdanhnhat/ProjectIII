import type { Meta } from "./types";

/** ApiError carries the HTTP status so callers can branch on 401/404/409. */
export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

interface RequestOptions {
  token?: string;
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

/** apiFetch is the only place that talks to the server. */
export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers({ Accept: "application/json" });
  if (options.token) headers.set("Authorization", `Bearer ${options.token}`);
  if (options.body !== undefined) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(path, {
      method: options.method ?? "GET",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      cache: "no-store",
      signal: options.signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Network error — is the server reachable?", 0);
  }

  if (!response.ok) {
    const text = (await response.text()).trim();
    throw new ApiError(text || `${response.status} ${response.statusText}`.trim(), response.status);
  }
  return (await response.json()) as T;
}

export function fetchMeta(token: string, signal?: AbortSignal): Promise<Meta> {
  return apiFetch<Meta>("/v1/meta", { token, signal });
}
