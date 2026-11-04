import { apiFetchBlob } from "../api/client";
import { fileName } from "./format";

/** Downloads one artifact and hands it to the browser as a file. */
export async function downloadArtifact(
  token: string,
  jobId: string,
  artifactId: string,
  source: string,
): Promise<void> {
  const blob = await apiFetchBlob(`/v1/jobs/${encodeURIComponent(jobId)}/artifacts/${encodeURIComponent(artifactId)}`, {
    token,
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName(source, artifactId);
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}
