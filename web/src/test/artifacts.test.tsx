import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ArtifactCard } from "../components/detail/ArtifactCard";
import type { Artifact, Job } from "../api/types";
import { JOB } from "./fixtures";
import { renderApp } from "./render";

function memoryJob(size: number): { job: Job; artifact: Artifact } {
  const artifact: Artifact = {
    id: "mem1",
    kind: "memory_image",
    source: "C:\\DFIR\\memory\\image.raw",
    reason: "full physical memory image captured with winpmem-mini",
    sha256: "c".repeat(64),
    size,
    mode: "-rw-------",
    modified_at: "2026-11-18T12:00:00Z",
    collected_at: "2026-11-18T12:00:00Z",
    stored_at: "artifacts/job/mem1",
  };
  return { job: { ...JOB, id: "memjob", scenario: "memory.v1", artifacts: [artifact] }, artifact };
}

describe("ArtifactCard", () => {
  it("labels a memory image and offers the normal download for a small file", () => {
    const { job, artifact } = memoryJob(4 << 20);
    renderApp(<ArtifactCard job={job} artifact={artifact} token="token" />);
    expect(screen.getByText("Memory image")).toHaveClass("tag");
    expect(screen.getByRole("button", { name: /download/i })).toBeInTheDocument();
    expect(screen.queryByText(/Retrieve with curl/)).not.toBeInTheDocument();
  });

  it("replaces the blob download with a curl command above 512 MiB", () => {
    const { job, artifact } = memoryJob(700 * 1024 * 1024);
    renderApp(<ArtifactCard job={job} artifact={artifact} token="token" />);
    expect(screen.getByText("too large for the browser")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^download$/i })).not.toBeInTheDocument();
    const command = screen.getByText(/Retrieve with curl/).parentElement?.textContent ?? "";
    expect(command).toContain("/v1/jobs/memjob/artifacts/mem1");
    expect(command).toContain("$DFIR_OPERATOR_TOKEN");
    expect(command).not.toContain("Bearer token");
  });

  it("labels the capture manifest", () => {
    const { job, artifact } = memoryJob(1024);
    renderApp(
      <ArtifactCard job={job} artifact={{ ...artifact, id: "man1", kind: "memory_manifest" }} token="token" />,
    );
    expect(screen.getByText("Memory manifest")).toHaveClass("tag");
  });
});
