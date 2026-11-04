import { useTISettings } from "../../api/queries";
import { Button } from "../ui/Button";
import { Dialog, DialogHead } from "../ui/Dialog";
import { Skeleton } from "../ui/Skeleton";
import { ListsCard } from "./ListsCard";
import { VirusTotalCard } from "./VirusTotalCard";

interface TISettingsDialogProps {
  token: string;
  onClose: () => void;
}

export function TISettingsDialog({ token, onClose }: TISettingsDialogProps) {
  const query = useTISettings(token, true);

  return (
    <Dialog open onClose={onClose} labelledBy="ti-settings-title" className="settings-dialog">
      <DialogHead
        id="ti-settings-title"
        eyebrow="Automation"
        title="Threat Intel & Lists"
        onClose={onClose}
      />
      <div className="dialog-body settings-body">
        {query.error ? (
          <p className="field-error" role="alert">
            Could not load settings: {query.error.message}
          </p>
        ) : null}
        {query.data ? (
          <>
            <VirusTotalCard settings={query.data} token={token} onSaved={() => query.refetch()} />
            <ListsCard settings={query.data} token={token} />
          </>
        ) : query.isLoading ? (
          <div className="settings-skeleton">
            <Skeleton />
            <Skeleton />
            <Skeleton />
          </div>
        ) : null}
      </div>
      <footer className="dialog-foot">
        <Button onClick={onClose}>Done</Button>
      </footer>
    </Dialog>
  );
}
