import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { NewJobDialog } from "../components/jobs/NewJobDialog";
import { META } from "./fixtures";
import { calls, resetCalls, server } from "./msw";
import { renderApp } from "./render";

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetCalls();
});
afterAll(() => server.close());

describe("new collection dialog", () => {
  it("requires a host id", async () => {
    renderApp(
      <NewJobDialog
        open
        token="test-token"
        defaultHost=""
        scenarios={META.scenarios}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Queue collection" }));
    expect(await screen.findByText("Host ID is required.")).toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });

  it("queues the collection and reports the created job", async () => {
    const onCreated = vi.fn();
    renderApp(
      <NewJobDialog
        open
        token="test-token"
        defaultHost="lab-ubuntu"
        scenarios={META.scenarios}
        onClose={() => {}}
        onCreated={onCreated}
      />,
    );

    await userEvent.selectOptions(screen.getByLabelText("Scenario"), "eventlog.v1");
    await userEvent.click(screen.getByRole("button", { name: "Queue collection" }));

    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    const body = calls.find((call) => call.path === "/v1/jobs")?.body;
    expect(body).toMatchObject({ host_id: "lab-ubuntu", scenario: "eventlog.v1" });
  });

  it("rejects a since date in the future", async () => {
    renderApp(
      <NewJobDialog
        open
        token="test-token"
        defaultHost="lab-ubuntu"
        scenarios={META.scenarios}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    const future = new Date(Date.now() + 3_600_000);
    const local = new Date(future.getTime() - future.getTimezoneOffset() * 60_000)
      .toISOString()
      .slice(0, 16);
    const input = screen.getByLabelText(/Modified since/);
    await userEvent.type(input, local);
    await userEvent.click(screen.getByRole("button", { name: "Queue collection" }));
    expect(await screen.findByText(/cannot be in the future/)).toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });
});
