import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { Dashboard } from "../components/layout/Dashboard";
import { META } from "./fixtures";
import { calls, resetCalls, server } from "./msw";
import { renderApp } from "./render";

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetCalls();
});
afterAll(() => server.close());

const dashboard = () => renderApp(<Dashboard token="test-token" meta={META} />);

describe("dashboard", () => {
  it("renders collections with stats and filters", async () => {
    dashboard();
    expect(await screen.findByText("lab-ubuntu")).toBeInTheDocument();
    expect(screen.getByText("Collections")).toBeInTheDocument();
    expect(screen.getByText("netstat.v1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Completed/ })).toBeInTheDocument();
    expect(screen.getByText("1 total")).toBeInTheDocument();
  });

  it("filters by search text", async () => {
    dashboard();
    const search = screen.getByLabelText("Filter collections");
    await userEvent.type(search, "no-such-host");
    expect(await screen.findByText("No matching collections")).toBeInTheDocument();
  });

  it("opens the detail sheet with triage findings", async () => {
    dashboard();
    await userEvent.click(await screen.findByRole("button", { name: /Open collection/ }));

    expect(await screen.findByRole("heading", { name: "Threat Intel" })).toBeInTheDocument();
    expect(await screen.findByText("93.184.216.34")).toBeInTheDocument();
    expect(screen.getByText("7/92")).toBeInTheDocument();
    expect(screen.getByText("Malicious")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Connections/ }));
    expect(await screen.findByText("93.184.216.34:443")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /DNS cache/ }));
    expect(await screen.findByText("portal.example.com")).toBeInTheDocument();
  });

  it("whitelists an indicator and re-runs the check", async () => {
    dashboard();
    await userEvent.click(await screen.findByRole("button", { name: /Open collection/ }));
    await screen.findByText("93.184.216.34");

    await userEvent.click(screen.getByRole("button", { name: "Whitelist 93.184.216.34" }));

    await waitFor(() => {
      expect(calls.some((call) => call.method === "POST" && call.path === "/v1/whitelist")).toBe(true);
      expect(
        calls.some((call) => call.method === "POST" && call.path.endsWith("/ti")),
      ).toBe(true);
    });
    const entry = calls.find((call) => call.path === "/v1/whitelist");
    expect(entry?.body).toMatchObject({ value: "93.184.216.34" });
  });

  it("blacklists an indicator from the findings table", async () => {
    dashboard();
    await userEvent.click(await screen.findByRole("button", { name: /Open collection/ }));
    await screen.findByText("cdn.example.net");

    await userEvent.click(screen.getByRole("button", { name: "Blacklist cdn.example.net" }));

    await waitFor(() => {
      expect(calls.some((call) => call.method === "POST" && call.path === "/v1/blacklist")).toBe(true);
    });
    const entry = calls.find((call) => call.path === "/v1/blacklist");
    expect(entry?.body).toMatchObject({ value: "cdn.example.net" });
  });
});
