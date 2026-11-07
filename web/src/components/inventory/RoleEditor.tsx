import { useState } from "react";
import type { Host, HostRole } from "../../api/types";
import { ROLE_LABELS, ROLE_ORDER } from "../../lib/hostRoles";
import { Button } from "../ui/Button";
import { Field, TextInput } from "../ui/Field";

interface RoleEditorProps {
  host: Host;
  roleOptions: HostRole[];
  saving: boolean;
  resetting: boolean;
  onApply: (roles: HostRole[], note: string) => void;
  onReset: () => void;
}

export function RoleEditor({ host, roleOptions, saving, resetting, onApply, onReset }: RoleEditorProps) {
  const initial = host.manual_roles?.length ? host.manual_roles : host.effective_roles;
  const [selected, setSelected] = useState<HostRole[]>(initial);
  const [note, setNote] = useState(host.manual_note ?? "");
  const [error, setError] = useState("");

  const options = ROLE_ORDER.filter((role) => roleOptions.includes(role));

  function toggle(role: HostRole) {
    setSelected((current) =>
      current.includes(role) ? current.filter((entry) => entry !== role) : [...current, role],
    );
    setError("");
  }

  function apply() {
    if (selected.length === 0) {
      setError("Select at least one role, or reset to automatic.");
      return;
    }
    const ordered = ROLE_ORDER.filter((role) => selected.includes(role));
    onApply(ordered, note.trim());
  }

  return (
    <div className="role-editor">
      <fieldset className="role-fieldset">
        <legend className="field-label">Manual roles</legend>
        <p className="field-hint">
          A manual set replaces the automatic result. The agent keeps it locally and stops
          re-detecting until you reset to automatic.
        </p>
        <div className="role-options">
          {options.map((role) => (
            <label className="role-option" key={role}>
              <input
                type="checkbox"
                checked={selected.includes(role)}
                onChange={() => toggle(role)}
              />
              <span>{ROLE_LABELS[role]}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <Field label="Note" htmlFor="role-note" optional hint="Stored with the override, max 200 characters.">
        <TextInput
          id="role-note"
          value={note}
          maxLength={200}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Why was this override applied?"
        />
      </Field>

      {error ? (
        <p className="field-error" role="alert">
          {error}
        </p>
      ) : null}

      <div className="role-editor-actions">
        {host.role_source === "manual" ? (
          <Button onClick={onReset} busy={resetting} disabled={saving}>
            Reset to automatic
          </Button>
        ) : null}
        <Button variant="primary" onClick={apply} busy={saving} disabled={resetting}>
          Apply manual roles
        </Button>
      </div>
    </div>
  );
}
