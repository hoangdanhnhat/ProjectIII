import { useState, type FormEvent } from "react";
import type { Job } from "../../api/types";
import { useCreateJob } from "../../api/queries";
import { Button } from "../ui/Button";
import { Dialog, DialogHead } from "../ui/Dialog";
import { Field, TextInput } from "../ui/Field";

interface NewJobDialogProps {
  open: boolean;
  onClose: () => void;
  token: string;
  defaultHost: string;
  scenarios: string[];
  onCreated: (job: Job) => void;
}

export function NewJobDialog(props: NewJobDialogProps) {
  if (!props.open) return null;
  return <NewJobForm {...props} />;
}

function NewJobForm({ onClose, token, defaultHost, scenarios, onCreated }: NewJobDialogProps) {
  const [host, setHost] = useState(defaultHost);
  const [scenario, setScenario] = useState(scenarios[0] ?? "netstat.v1");
  const [since, setSince] = useState("");
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
    let sinceISO: string | undefined;
    if (since) {
      const parsed = new Date(since);
      if (Number.isNaN(parsed.getTime())) {
        setError("The date is not valid.");
        return;
      }
      if (parsed.getTime() > Date.now() + 60_000) {
        setError("“Modified since” cannot be in the future.");
        return;
      }
      sinceISO = parsed.toISOString();
    }
    try {
      const job = await create.mutateAsync({ host_id: hostValue, scenario, since: sinceISO });
      onCreated(job);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not queue the collection.");
    }
  }

  return (
    <Dialog open onClose={onClose} labelledBy="new-job-title">
      <form onSubmit={submit} noValidate>
        <DialogHead id="new-job-title" eyebrow="New job" title="Request a collection" onClose={onClose} />
        <div className="dialog-body">
          <Field label="Host ID" htmlFor="host-input">
            <TextInput
              id="host-input"
              value={host}
              onChange={(event) => setHost(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="lab-ubuntu"
              autoFocus
            />
          </Field>
          <Field label="Scenario" htmlFor="scenario-input">
            <select
              id="scenario-input"
              className="field-input"
              value={scenario}
              onChange={(event) => setScenario(event.target.value)}
            >
              {scenarios.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="Modified since"
            htmlFor="since-input"
            optional
            hint="Only collect files changed after this moment (webshell.v1)."
          >
            <TextInput
              id="since-input"
              type="datetime-local"
              value={since}
              onChange={(event) => setSince(event.target.value)}
            />
          </Field>
          {error ? (
            <p className="field-error" role="alert">
              {error}
            </p>
          ) : null}
        </div>
        <footer className="dialog-foot">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={create.isPending}>
            {create.isPending ? "Queueing…" : "Queue collection"}
          </Button>
        </footer>
      </form>
    </Dialog>
  );
}
