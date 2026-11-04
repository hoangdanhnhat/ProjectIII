// Hand-written mirrors of the Go API structs. Keep this file the single
// source of truth for every payload the console consumes; phases 2-4 add
// Job, Artifact, TIReport and list types here.

export interface Meta {
  host_id: string;
  scenarios: string[];
}
