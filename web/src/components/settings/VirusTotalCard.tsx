import { useState, type FormEvent } from "react";
import type { TISettings } from "../../api/types";
import { useUpdateTISettings } from "../../api/queries";
import { Button } from "../ui/Button";
import { Chip } from "../ui/Chip";
import { Field, TextInput } from "../ui/Field";
import { useToast } from "../ui/toast-context";

interface VirusTotalCardProps {
  settings: TISettings;
  token: string;
  onSaved: () => void;
}

export function VirusTotalCard({ settings, token, onSaved }: VirusTotalCardProps) {
  const vt = settings.vt;
  const [apiKey, setApiKey] = useState("");
  const [reveal, setReveal] = useState(false);
  const [auto, setAuto] = useState(vt.auto_enrich);
  const [rate, setRate] = useState(String(vt.rate_per_min));
  const [max, setMax] = useState(String(vt.max_queries_per_job));
  const [error, setError] = useState("");
  const update = useUpdateTISettings(token);
  const toast = useToast();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const rateValue = Number.parseInt(rate, 10);
    const maxValue = Number.parseInt(max, 10);
    if (!Number.isFinite(rateValue) || rateValue < 1 || rateValue > 60) {
      setError("Rate limit must be between 1 and 60 requests per minute.");
      return;
    }
    if (!Number.isFinite(maxValue) || maxValue < 1 || maxValue > 500) {
      setError("Max checks must be between 1 and 500 per collection.");
      return;
    }
    try {
      await update.mutateAsync({
        vt_auto_enrich: auto,
        vt_rate_per_min: rateValue,
        vt_max_queries_per_job: maxValue,
        ...(apiKey.trim() ? { vt_api_key: apiKey.trim() } : {}),
      });
      setApiKey("");
      toast("Threat Intel settings saved.", "success");
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save settings.");
    }
  }

  return (
    <form className="ti-card" onSubmit={submit} noValidate>
      <div className="ti-card-head">
        <h3>VirusTotal</h3>
        <Chip tone={vt.configured ? "green" : "neutral"}>
          {vt.configured ? `Configured ${vt.key_preview}` : "Not configured"}
        </Chip>
      </div>
      <p className="field-hint">
        Public IPs and domains from netstat.v1 collections are checked against VirusTotal. The key
        is stored on the server only and never sent back to the browser.
      </p>
      <Field label="API key" htmlFor="vt-key" optional>
        <span className="input-wrap">
          <TextInput
            id="vt-key"
            type={reveal ? "text" : "password"}
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder={vt.configured ? "Configured — paste a new key to replace it" : "Paste a key to enable checks"}
            autoComplete="off"
            spellCheck={false}
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
      <label className="switch-row">
        <input
          className="switch-input"
          type="checkbox"
          checked={auto}
          onChange={(event) => setAuto(event.target.checked)}
        />
        <span className="switch-track" aria-hidden="true" />
        <span className="switch-text">Auto-check indicators when a collection completes</span>
      </label>
      <div className="ti-grid">
        <Field label="Rate limit" htmlFor="vt-rate" hint="per minute">
          <TextInput
            id="vt-rate"
            type="number"
            min={1}
            max={60}
            value={rate}
            onChange={(event) => setRate(event.target.value)}
          />
        </Field>
        <Field label="Max checks" htmlFor="vt-max" hint="per collection">
          <TextInput
            id="vt-max"
            type="number"
            min={1}
            max={500}
            value={max}
            onChange={(event) => setMax(event.target.value)}
          />
        </Field>
      </div>
      {error ? (
        <p className="field-error" role="alert">
          {error}
        </p>
      ) : null}
      <div className="ti-actions">
        <Button type="submit" variant="primary" busy={update.isPending}>
          Save settings
        </Button>
      </div>
    </form>
  );
}
