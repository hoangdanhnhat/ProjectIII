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

/** Fired on any 401 so the session layer can drop the token. */
export const UNAUTHORIZED_EVENT = "dfir:unauthorized";

interface RequestOptions {
  token?: string;
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

function fail(status: number, message: string): never {
  if (status === 401) window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
  throw new ApiError(message, status);
}

async function request(path: string, options: RequestOptions): Promise<Response> {
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
    fail(response.status, text || `${response.status} ${response.statusText}`.trim());
  }
  return response;
}

/** apiFetch is the only JSON path to the server. */
export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await request(path, options);
  return (await response.json()) as T;
}

/** apiFetchBlob downloads evidence bytes (used for artifact downloads). */
export async function apiFetchBlob(path: string, options: RequestOptions = {}): Promise<Blob> {
  const response = await request(path, options);
  return response.blob();
}

export function fetchMeta(token: string, signal?: AbortSignal): Promise<Meta> {
  return apiFetch<Meta>("/v1/meta", { token, signal });
}
