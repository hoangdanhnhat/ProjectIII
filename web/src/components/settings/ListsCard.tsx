import { useState, type FormEvent } from "react";
import type { ListEntry, ListName, TISettings } from "../../api/types";
import { useAddListEntry, useRemoveListEntry } from "../../api/queries";
import { relative } from "../../lib/format";
import { Button } from "../ui/Button";
import { Tag } from "../ui/Tag";
import { Icon } from "../ui/Icon";
import { useToast } from "../ui/toast-context";

const TYPE_LABELS: Record<ListEntry["type"], string> = {
  ip: "IP",
  cidr: "Network",
  domain: "Domain",
  domain_wildcard: "Wildcard",
};

const HINTS: Record<ListName, string> = {
  whitelist:
    "Trusted values: shown in reports but never sent to VirusTotal. Examples: 1.1.1.1, 10.0.0.0/8, example.com, *.example.com.",
  blacklist:
    "Known-bad values: shown with verdict Blacklisted and never sent to VirusTotal. The blacklist wins when a value is on both lists.",
};

interface ListsCardProps {
  settings: TISettings;
  token: string;
}

export function ListsCard({ settings, token }: ListsCardProps) {
  const [list, setList] = useState<ListName>("whitelist");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  const add = useAddListEntry(token);
  const remove = useRemoveListEntry(token);
  const toast = useToast();

  const counts: Record<ListName, number> = {
    whitelist: settings.whitelist.entries.length,
    blacklist: settings.blacklist.entries.length,
  };
  const entries = settings[list].entries;
  const visible = entries.filter(
    (entry) => !filter || entry.value.toLowerCase().includes(filter.toLowerCase()),
  );

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const candidate = value.trim();
    if (!candidate) {
      setError("Enter an IP, CIDR, domain or *.wildcard value.");
      return;
    }
    try {
      await add.mutateAsync({ list, value: candidate, note: note.trim() });
      setValue("");
      setNote("");
      toast(`${list === "blacklist" ? "Blacklisted" : "Whitelisted"} ${candidate}`, "success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add the entry.");
    }
  }

  async function removeEntry(entry: ListEntry) {
    try {
      await remove.mutateAsync({ list, id: entry.id });
      toast(`Removed ${entry.value} from the ${list}.`);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not remove the entry.", "error");
    }
  }

  return (
    <section className="ti-card">
      <div className="ti-card-head">
        <h3>Indicator lists</h3>
      </div>
      <div className="tabs" role="group" aria-label="Indicator lists">
        {(["whitelist", "blacklist"] as ListName[]).map((name) => (
          <button
            key={name}
            type="button"
            className={name === list ? "tab is-active" : "tab"}
            aria-pressed={name === list}
            onClick={() => {
              setList(name);
              setError("");
            }}
          >
            {name === "whitelist" ? "Whitelist" : "Blacklist"} <span className="count">{counts[name]}</span>
          </button>
        ))}
      </div>
      <p className="field-hint">{HINTS[list]}</p>

      <form className="list-add" onSubmit={submit} noValidate>
        <input
          className="field-input"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={list === "blacklist" ? "Known-bad IP, CIDR, domain or *.wildcard" : "IP, CIDR, domain or *.wildcard"}
          aria-label="List value"
          autoComplete="off"
          spellCheck={false}
        />
        <input
          className="field-input"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Note (optional)"
          aria-label="List note"
          autoComplete="off"
        />
        <Button type="submit" variant="primary" busy={add.isPending}>
          Add
        </Button>
      </form>
      {error ? (
        <p className="field-error" role="alert">
          {error}
        </p>
      ) : null}

      <div className="search">
        <Icon name="search" className="icon search-icon" />
        <input
          type="search"
          placeholder="Filter list…"
          aria-label="Filter list"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          autoComplete="off"
        />
      </div>

      {visible.length === 0 ? (
        <p className="mini-empty">
          {entries.length
            ? "Nothing matches this filter."
            : list === "blacklist"
              ? "The blacklist is empty — all public indicators go through VirusTotal."
              : "The whitelist is empty — every public indicator will be checked."}
        </p>
      ) : (
        <ul className="list-rows" aria-label="Indicator list entries">
          {visible.map((entry) => (
            <li className="list-row" key={entry.id}>
              <Tag>{TYPE_LABELS[entry.type] ?? entry.type}</Tag>
              <span className="list-main">
                <span className="mono list-value">{entry.value}</span>
                {entry.note ? (
                  <span className="list-note" title={entry.note}>
                    {entry.note}
                  </span>
                ) : null}
              </span>
              <span className="list-added" title={entry.created_at}>
                {relative(entry.created_at)}
              </span>
              <button
                type="button"
                className="icon-btn icon-btn--danger"
                onClick={() => removeEntry(entry)}
                aria-label={`Remove ${entry.value} from the ${list}`}
                title="Remove"
              >
                <Icon name="trash" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
