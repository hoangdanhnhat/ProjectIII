import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { JOB, REPORT, SNAPSHOT, TI_SETTINGS } from "./fixtures";

export const calls: Array<{ method: string; path: string; body: unknown }> = [];

export function resetCalls(): void {
  calls.length = 0;
}

function record(method: string, path: string, body: unknown = null): void {
  calls.push({ method, path, body });
}

export const handlers = [
  http.get("*/v1/jobs", () => HttpResponse.json({ jobs: [JOB] })),

  http.post("*/v1/jobs", async ({ request }) => {
    const body = await request.json();
    record("POST", "/v1/jobs", body);
    return HttpResponse.json({ ...JOB, id: "new-job-0001", status: "queued" }, { status: 201 });
  }),

  http.get("*/v1/jobs/:id/artifacts/:artifact", ({ params }) => {
    if (params.artifact === "rep1") return HttpResponse.json(REPORT);
    if (params.artifact === "snap1") return HttpResponse.json(SNAPSHOT);
    return new HttpResponse(null, { status: 404 });
  }),

  http.get("*/v1/settings/ti", () => HttpResponse.json(TI_SETTINGS)),

  http.put("*/v1/settings/ti", async ({ request }) => {
    const body = await request.json();
    record("PUT", "/v1/settings/ti", body);
    return HttpResponse.json(TI_SETTINGS);
  }),

  http.post("*/v1/whitelist", async ({ request }) => {
    const body = await request.json();
    record("POST", "/v1/whitelist", body);
    return HttpResponse.json(
      { id: "w-new", value: "1.2.3.4", type: "ip", created_at: new Date().toISOString() },
      { status: 201 },
    );
  }),

  http.post("*/v1/blacklist", async ({ request }) => {
    const body = await request.json();
    record("POST", "/v1/blacklist", body);
    return HttpResponse.json(
      { id: "b-new", value: "1.2.3.4", type: "ip", created_at: new Date().toISOString() },
      { status: 201 },
    );
  }),

  http.delete("*/v1/whitelist/:id", ({ params }) => {
    record("DELETE", `/v1/whitelist/${params.id}`);
    return new HttpResponse(null, { status: 204 });
  }),

  http.delete("*/v1/blacklist/:id", ({ params }) => {
    record("DELETE", `/v1/blacklist/${params.id}`);
    return new HttpResponse(null, { status: 204 });
  }),

  http.post("*/v1/jobs/:id/ti", ({ params }) => {
    record("POST", `/v1/jobs/${params.id}/ti`);
    return HttpResponse.json({ ...JOB, ti_status: "running" }, { status: 202 });
  }),
];

export const server = setupServer(...handlers);
