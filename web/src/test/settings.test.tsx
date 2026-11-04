import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { TISettingsDialog } from "../components/settings/TISettingsDialog";
import { calls, resetCalls, server } from "./msw";
import { renderApp } from "./render";

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetCalls();
});
afterAll(() => server.close());

const open = () => renderApp(<TISettingsDialog token="test-token" onClose={() => {}} />);

describe("threat intel settings", () => {
  it("shows the masked key and both lists", async () => {
    open();
    expect(await screen.findByText(/Configured .*abcd/)).toBeInTheDocument();
    expect(await screen.findByText("*.microsoft.com")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Blacklist/ }));
    expect(await screen.findByText("203.0.113.66")).toBeInTheDocument();
  });

  it("adds a blacklist entry", async () => {
    open();
    await userEvent.click(await screen.findByRole("button", { name: /Blacklist/ }));
    await userEvent.type(screen.getByLabelText("List value"), "198.51.100.7");
    await userEvent.type(screen.getByLabelText("List note"), "operator finding");
    await userEvent.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() => {
      expect(calls.some((call) => call.method === "POST" && call.path === "/v1/blacklist")).toBe(true);
    });
    const body = calls.find((call) => call.path === "/v1/blacklist")?.body;
    expect(body).toMatchObject({ value: "198.51.100.7", note: "operator finding" });
  });

  it("removes a whitelist entry", async () => {
    open();
    await userEvent.click(await screen.findByRole("button", { name: /Remove localhost/ }));
    await waitFor(() => {
      expect(calls.some((call) => call.method === "DELETE" && call.path === "/v1/whitelist/w2")).toBe(true);
    });
  });

  it("saves VirusTotal settings", async () => {
    open();
    const rate = await screen.findByLabelText(/Rate limit/);
    await userEvent.clear(rate);
    await userEvent.type(rate, "10");
    await userEvent.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() => {
      expect(calls.some((call) => call.method === "PUT")).toBe(true);
    });
    const body = calls.find((call) => call.method === "PUT")?.body;
    expect(body).toMatchObject({ vt_rate_per_min: 10, vt_auto_enrich: true });
  });
});
