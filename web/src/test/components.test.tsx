import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Button } from "../components/ui/Button";
import { Chip } from "../components/ui/Chip";
import { Tag } from "../components/ui/Tag";

describe("Button", () => {
  it("renders the primary variant and fires clicks", async () => {
    const onClick = vi.fn();
    render(
      <Button variant="primary" onClick={onClick}>
        Connect
      </Button>,
    );
    const button = screen.getByRole("button", { name: "Connect" });
    expect(button).toHaveClass("btn", "btn--primary");
    await userEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("is disabled while busy", () => {
    render(<Button busy>Working</Button>);
    expect(screen.getByRole("button", { name: "Working" })).toBeDisabled();
  });
});

describe("Chip", () => {
  it("marks risk tones", () => {
    render(<Chip tone="red">Malicious</Chip>);
    expect(screen.getByText("Malicious").closest(".chip")).toHaveAttribute("data-tone", "red");
  });

  it("keeps neutral chips untoned", () => {
    render(<Chip>Queued</Chip>);
    expect(screen.getByText("Queued").closest(".chip")).not.toHaveAttribute("data-tone");
  });
});

describe("Tag", () => {
  it("renders a category label", () => {
    render(<Tag>IP</Tag>);
    expect(screen.getByText("IP")).toHaveClass("tag");
  });
});
