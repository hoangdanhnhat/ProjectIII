import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, apiFetchBlob } from "./client";
import type {
  CreateJobInput,
  DNSRecord,
  Job,
  ListEntry,
  ListName,
  SnapshotConnection,
  TISettings,
  TIReport,
  UpdateTISettingsInput,
} from "./types";

/** Central query keys: invalidate exactly these after a mutation. */
export const qk = {
  jobs: () => ["jobs"] as const,
  job: (id: string) => ["jobs", id] as const,
  tiSettings: () => ["ti-settings"] as const,
  artifact: (jobId: string, artifactId: string) => ["artifact", jobId, artifactId] as const,
};

export function useJobs(token: string) {
  return useQuery({
    queryKey: qk.jobs(),
    queryFn: ({ signal }) => apiFetch<{ jobs: Job[] }>("/v1/jobs", { token, signal }),
    enabled: token !== "",
    refetchInterval: 5000,
    refetchIntervalInBackground: false,
    staleTime: 2000,
  });
}

export function useTISettings(token: string, enabled: boolean) {
  return useQuery({
    queryKey: qk.tiSettings(),
    queryFn: ({ signal }) => apiFetch<TISettings>("/v1/settings/ti", { token, signal }),
    enabled: enabled && token !== "",
    staleTime: 5000,
  });
}

/** Artifact IDs are content-addressed, so a fetched body never goes stale. */
export function useArtifactJSON<T>(token: string, jobId: string, artifactId: string | null) {
  return useQuery({
    queryKey: qk.artifact(jobId, artifactId ?? "none"),
    queryFn: async ({ signal }): Promise<T | null> => {
      if (!artifactId) return null;
      const blob = await apiFetchBlob(`/v1/jobs/${jobId}/artifacts/${artifactId}`, { token, signal });
      try {
        return (JSON.parse(await blob.text()) as T) ?? null;
      } catch {
        return null;
      }
    },
    enabled: token !== "" && artifactId !== null,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  });
}

export function useCreateJob(token: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateJobInput) =>
      apiFetch<Job>("/v1/jobs", { token, method: "POST", body: input }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.jobs() }),
  });
}

export function useUpdateTISettings(token: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: UpdateTISettingsInput) =>
      apiFetch<TISettings>("/v1/settings/ti", { token, method: "PUT", body: input }),
    onSuccess: (data) => queryClient.setQueryData(qk.tiSettings(), data),
  });
}

export function useAddListEntry(token: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ list, value, note }: { list: ListName; value: string; note: string }) =>
      apiFetch<ListEntry>(`/v1/${list}`, { token, method: "POST", body: { value, note } }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.tiSettings() }),
  });
}

export function useRemoveListEntry(token: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ list, id }: { list: ListName; id: string }) => {
      // The endpoint answers 204 with no body; blob() handles that fine.
      await apiFetchBlob(`/v1/${list}/${encodeURIComponent(id)}`, { token, method: "DELETE" });
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.tiSettings() }),
  });
}

export function useRerunTI(token: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) =>
      apiFetch<Job>(`/v1/jobs/${encodeURIComponent(jobId)}/ti`, { token, method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.jobs() }),
  });
}

// Re-exported so components can decode artifacts without importing shapes
// from the hooks file.
export type { DNSRecord, SnapshotConnection, TIReport };
