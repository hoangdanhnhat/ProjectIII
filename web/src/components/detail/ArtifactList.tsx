import type { Job } from "../../api/types";
import { ArtifactCard } from "./ArtifactCard";

export function ArtifactList({ job, token }: { job: Job; token: string }) {
  const artifacts = Array.isArray(job.artifacts) ? job.artifacts : [];

  return (
    <section className="section">
      <div className="section-head">
        <h3>Artifacts</h3>
        <span className="count">{artifacts.length}</span>
      </div>
      {artifacts.length === 0 ? (
        <div className="mini-empty">
          {job.status === "running"
            ? "Waiting for the agent to upload artifacts…"
            : "No artifacts were uploaded for this collection."}
        </div>
      ) : (
        <div className="artifact-list">
          {artifacts.map((artifact) => (
            <ArtifactCard key={artifact.id} job={job} artifact={artifact} token={token} />
          ))}
        </div>
      )}
    </section>
  );
}
