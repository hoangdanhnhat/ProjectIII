import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { HostRoleCard } from "../components/detail/HostRoleCard";
import { ROLE_JOB } from "./fixtures";
import { resetCalls, server } from "./msw";
import { renderApp } from "./render";

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetCalls();
});
afterAll(() => server.close());

describe("host role card", () => {
  it("shows the primary role, host class and every scored role", async () => {
    renderApp(<HostRoleCard job={ROLE_JOB} token="test-token" />);

    expect(await screen.findByRole("heading", { name: "Host role" })).toBeInTheDocument();
    expect(await screen.findByText(/WIN-WEB01/)).toBeInTheDocument();
    expect(screen.getByText(/Windows Server 2022 Standard/)).toBeInTheDocument();
    expect(screen.getAllByText("Web server (IIS)").length).toBeGreaterThan(0);
    expect(screen.getByText("Confirmed")).toBeInTheDocument();
    expect(screen.getByText("100%")).toBeInTheDocument();
    expect(screen.getByText("File server (SMB)")).toBeInTheDocument();
    expect(screen.getByText("65%")).toBeInTheDocument();
  });

  it("expands the evidence behind a role", async () => {
    renderApp(<HostRoleCard job={ROLE_JOB} token="test-token" />);
    await screen.findAllByText("Web server (IIS)");

    await userEvent.click(screen.getByText("2 evidence items"));

    expect(screen.getByText(/IIS configuration file present/)).toBeInTheDocument();
    expect(screen.getByText(/service present, Start=auto/)).toBeInTheDocument();
  });
});
