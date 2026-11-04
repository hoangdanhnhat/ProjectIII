import { useState, type FormEvent } from "react";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";

interface ConnectViewProps {
  error: string;
  onConnect: (token: string) => Promise<void>;
  onClearError: () => void;
}

export function ConnectView({ error, onConnect, onClearError }: ConnectViewProps) {
  const [token, setToken] = useState("");
  const [reveal, setReveal] = useState(false);
  const [localError, setLocalError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = token.trim();
    if (!value) {
      setLocalError("Enter the operator token.");
      return;
    }
    setLocalError("");
    onClearError();
    setBusy(true);
    try {
      await onConnect(value);
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : "Could not connect.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="connect">
      <div className="connect-card">
        <div className="eyebrow">Operator access</div>
        <h1>Sign in</h1>
        <p className="lede">
          Use the operator token configured on the server. The agent token does not grant access
          here.
        </p>
        <form className="connect-form" onSubmit={submit} noValidate>
          <Field label="Operator token" htmlFor="operator-token">
            <span className="input-wrap">
              <input
                id="operator-token"
                className="field-input"
                type={reveal ? "text" : "password"}
                value={token}
                onChange={(event) => setToken(event.target.value)}
                autoComplete="current-password"
                spellCheck={false}
                placeholder="Paste your operator token"
                autoFocus
              />
              <button
                type="button"
                className="input-action"
                onClick={() => setReveal((value) => !value)}
                aria-pressed={reveal}
              >
                {reveal ? "Hide" : "Show"}
              </button>
            </span>
          </Field>
          {localError || error ? (
            <p className="field-error" role="alert">
              {localError || error}
            </p>
          ) : null}
          <Button type="submit" variant="primary" block busy={busy}>
            {busy ? "Connecting…" : "Connect"}
          </Button>
        </form>
        <p className="fineprint">
          The token stays in this tab&apos;s session storage and is sent as a Bearer header. Use
          HTTPS whenever the server is not on loopback.
        </p>
      </div>
    </section>
  );
}
