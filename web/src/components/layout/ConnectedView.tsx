import { Tag } from "../ui/Tag";

interface ConnectedViewProps {
  hostId: string;
  scenarios: string[];
}

/** Temporary landing view for the migration phase; replaced in phase 3. */
export function ConnectedView({ hostId, scenarios }: ConnectedViewProps) {
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Connected</div>
          <h1>Console migration in progress</h1>
          <p className="lede">
            The new shell is live. Collections, triage and settings move here in the next phases;
            the existing console keeps serving the root URL until cutover.
          </p>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Server</h2>
          <span className="statusline">
            <span className="status-dot" data-state="ok" />
            Connected
          </span>
        </div>
        <div className="panel-body">
          <dl className="kv">
            <dt>Host ID</dt>
            <dd className="mono">{hostId}</dd>
            <dt>Scenarios</dt>
            <dd>{scenarios.map((name) => <Tag key={name}>{name}</Tag>)}</dd>
          </dl>
        </div>
      </section>
    </>
  );
}
