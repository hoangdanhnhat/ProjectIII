import { useState, type FormEvent } from "react";
import type { Job } from "../../api/types";
import { useCreateJob } from "../../api/queries";
import { MEMORY_SCENARIO } from "../../lib/memory";
import { Button } from "../ui/Button";
import { Dialog, DialogHead } from "../ui/Dialog";
import { Field, TextInput } from "../ui/Field";

interface MemoryCaptureDialogProps {
  open: boolean;
  onClose: () => void;
  token: string;
  defaultHost: string;
  hosts?: string[];
  onCreated: (job: Job) => void;
}

export function MemoryCaptureDialog(props: MemoryCaptureDialogProps) {
  if (!props.open) return null;
  return <MemoryCaptureForm {...props} />;
}

function MemoryCaptureForm({
  onClose,
  token,
  defaultHost,
  hosts = [],
  onCreated,
}: MemoryCaptureDialogProps) {
  const [host, setHost] = useState(
    hosts.length > 0 ? (hosts.includes(defaultHost) ? defaultHost : hosts[0]) : defaultHost,
  );
  const [consent, setConsent] = useState(false);
  const [error, setError] = useState("");
  const create = useCreateJob(token);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const hostValue = host.trim();
    if (!hostValue) {
      setError("Host ID is required.");
      return;
    }
    if (!consent) {
      setError("Confirm that you understand what a memory capture contains.");
      return;
    }
    try {
      const job = await create.mutateAsync({ host_id: hostValue, scenario: MEMORY_SCENARIO });
      onCreated(job);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not queue the memory capture.");
    }
  }

  return (
    <Dialog open onClose={onClose} labelledBy="memory-capture-title">
      <form onSubmit={submit} noValidate>
        <DialogHead
          id="memory-capture-title"
          eyebrow="Memory capture"
          title="Capture physical memory"
          onClose={onClose}
        />
        <div className="dialog-body">
          <div className="callout" data-tone="amber">
            <span className="callout-label">Sensitive evidence</span>
            <p>
              The image contains the full physical RAM of the machine, including credentials,
              keys and other secrets. Handle it as sensitive evidence, keep it on trusted storage
              and delete copies you no longer need.
            </p>
          </div>

          <Field label="Host ID" htmlFor="memory-host-input">
            {hosts.length > 0 ? (
              <select
                id="memory-host-input"
                className="field-input"
                value={host}
                onChange={(event) => setHost(event.target.value)}
                autoFocus
              >
                {hosts.map((id) => (
                  <option key={id} value={id}>
                    {id}
                  </option>
                ))}
              </select>
            ) : (
              <TextInput
                id="memory-host-input"
                value={host}
                onChange={(event) => setHost(event.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="win-web01"
                autoFocus
              />
            )}
          </Field>
          <p className="field-hint">
            The agent must run elevated with <code className="mono">-memory-tool</code>,{" "}
            <code className="mono">-memory-tool-sha256</code> and{" "}
            <code className="mono">-memory-out</code>; otherwise the job returns{" "}
            <code className="mono">needs_configuration</code>. The capture may take minutes and
            needs free disk equal to the machine&apos;s RAM.
          </p>

          <label className="consent">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
            />
            <span>
              I understand this captures all physical memory and may contain credentials and other
              sensitive data.
            </span>
          </label>

          {error ? (
            <p className="field-error" role="alert">
              {error}
            </p>
          ) : null}
        </div>
        <footer className="dialog-foot">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="submit"
            variant="primary"
            busy={create.isPending}
            disabled={!consent || create.isPending}
          >
            {create.isPending ? "Queueing…" : "Queue capture"}
          </Button>
        </footer>
      </form>
    </Dialog>
  );
}
