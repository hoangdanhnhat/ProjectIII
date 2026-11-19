import { http, HttpResponse } from "msw";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { Job } from "../api/types";
import { MemoryPage } from "../components/memory/MemoryPage";
import { MEMORY_JOB } from "./memoryFixtures";
import { META } from "./fixtures";
import { calls, resetCalls, server } from "./msw";
import { renderApp } from "./render";

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetCalls();
});
afterAll(() => server.close());

function jobsResponse(jobs: Job[]) {
  server.use(http.get("*/v1/jobs", () => HttpResponse.json({ jobs })));
}

const page = () => renderApp(<MemoryPage token="test-token" meta={META} />);

describe("memory view", () => {
  it("explains when there are no captures yet", async () => {
    jobsResponse([]);
    page();
    expect(await screen.findByText("No memory captures yet")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "New memory capture" }).length).toBeGreaterThan(0);
  });

  it("lists captures and renders the manifest summary", async () => {
    jobsResponse([MEMORY_JOB]);
    page();

    const row = await screen.findByRole("button", {
      name: /Open memory capture mem-job-0001/,
    });
    expect(await screen.findByText("Completed")).toBeInTheDocument();
    expect(screen.getByText("2.0 GB")).toBeInTheDocument();

    await userEvent.click(row);

    expect(await screen.findByRole("heading", { name: "win-web01" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Capture manifest" })).toBeInTheDocument();
    expect(await screen.findByText("winpmem 4.0.1")).toBeInTheDocument();
    expect(screen.getByText("Completed · exit code 1")).toBeInTheDocument();
    expect(screen.getByText(/pagefile/)).toBeInTheDocument();
    expect(screen.getByText(/completed acquisition with exit code 1/)).toBeInTheDocument();

    // The Volatility analysis section renders the report and plugin table.
    expect(await screen.findByText(/2\/2 plugins/)).toBeInTheDocument();
    expect(screen.getAllByText("windows.pslist.PsList").length).toBeGreaterThan(0);
    const views = await screen.findAllByRole("button", { name: "View" });
    await userEvent.click(views[0]);
    expect(
      await screen.findByRole("table", { name: /windows\.pslist\.PsList rows/ }),
    ).toBeInTheDocument();
    expect(await screen.findByText("explorer.exe")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/Filter windows\.pslist\.PsList rows/), "system");
    await waitFor(() => expect(screen.queryByText("explorer.exe")).not.toBeInTheDocument());
    const closes = screen.getAllByRole("button", { name: "Close" });
    await userEvent.click(closes[closes.length - 1]);
  });

  it("re-runs memory analysis from the job sheet", async () => {
    jobsResponse([MEMORY_JOB]);
    page();

    await userEvent.click(
      await screen.findByRole("button", { name: /Open memory capture mem-job-0001/ }),
    );
    expect(await screen.findByText(/2\/2 plugins/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Re-run analysis" }));

    await waitFor(() => {
      expect(
        calls.some(
          (call) => call.method === "POST" && call.path === "/v1/jobs/mem-job-0001/volatility",
        ),
      ).toBe(true);
    });
  });

  it("requires explicit consent before queueing a capture", async () => {
    jobsResponse([MEMORY_JOB]);
    page();

    await userEvent.click(await screen.findByRole("button", { name: "New memory capture" }));
    const submit = screen.getByRole("button", { name: "Queue capture" });
    expect(submit).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox", { name: /I understand/ }));
    expect(submit).toBeEnabled();
    await userEvent.click(submit);

    await waitFor(() => {
      expect(calls.some((call) => call.method === "POST" && call.path === "/v1/jobs")).toBe(true);
    });
    const posted = calls.find((call) => call.method === "POST" && call.path === "/v1/jobs");
    expect(posted?.body).toMatchObject({ scenario: "memory.v1" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});
