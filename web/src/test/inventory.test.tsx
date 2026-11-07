import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { InventoryPage } from "../components/inventory/InventoryPage";
import { META } from "./fixtures";
import { calls, resetCalls, server } from "./msw";
import { renderApp } from "./render";

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetCalls();
});
afterAll(() => server.close());

const inventory = () => renderApp(<InventoryPage token="test-token" meta={META} />);

describe("machine inventory", () => {
  it("lists managed machines with roles and status", async () => {
    inventory();
    expect(await screen.findByText("WIN-WEB01")).toBeInTheDocument();
    expect(screen.getByText("WIN-DC01")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open machine lab-ubuntu" })).toBeInTheDocument();
    expect(screen.getAllByText("Web server (IIS)").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Workstation").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Online").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Stale").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Never seen").length).toBeGreaterThan(0);
  });

  it("filters by role and search text", async () => {
    inventory();
    await screen.findByText("WIN-WEB01");

    await userEvent.click(screen.getByRole("button", { name: "Domain controller" }));
    expect(screen.getByText("WIN-DC01")).toBeInTheDocument();
    expect(screen.queryByText("WIN-WEB01")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Domain controller" }));
    const search = screen.getByLabelText("Filter machines");
    await userEvent.type(search, "lab-ubuntu");
    expect(await screen.findByRole("button", { name: "Open machine lab-ubuntu" })).toBeInTheDocument();
    expect(screen.queryByText("WIN-WEB01")).not.toBeInTheDocument();
  });

  it("applies a manual role override", async () => {
    inventory();
    await userEvent.click(await screen.findByRole("button", { name: "Open machine WIN-WEB01" }));

    expect(await screen.findByRole("heading", { name: "WIN-WEB01" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("checkbox", { name: "Database server (MSSQL)" }));
    await userEvent.click(screen.getByRole("button", { name: "Apply manual roles" }));

    await waitFor(() => {
      expect(calls.some((call) => call.method === "PUT" && call.path.endsWith("/roles"))).toBe(true);
    });
    const entry = calls.find((call) => call.method === "PUT");
    expect(entry?.body).toMatchObject({ roles: ["web_server"] });
  });

  it("resets a manual override to automatic", async () => {
    inventory();
    await userEvent.click(await screen.findByRole("button", { name: "Open machine WIN-DC01" }));

    expect(await screen.findByRole("heading", { name: "WIN-DC01" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Reset to automatic" }));

    await waitFor(() => {
      expect(calls.some((call) => call.method === "DELETE" && call.path.endsWith("/roles"))).toBe(
        true,
      );
    });
  });
});
