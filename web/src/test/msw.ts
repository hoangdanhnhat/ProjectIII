import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { HOST_ROLE, JOB, REPORT, SNAPSHOT, TI_SETTINGS } from "./fixtures";
import {
  MEMORY_JOB,
  MEMORY_MANIFEST,
  VOL_MALFIND_ROWS,
  VOL_PSLIST_ROWS,
  VOL_REPORT,
} from "./memoryFixtures";
import { HOSTS } from "./hostFixtures";

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
    if (params.artifact === "role1") return HttpResponse.json(HOST_ROLE);
    if (params.artifact === "mem-manifest") return HttpResponse.json(MEMORY_MANIFEST);
    if (params.artifact === "vol-report") return HttpResponse.json(VOL_REPORT);
    if (params.artifact === "vol-pslist") return HttpResponse.text(VOL_PSLIST_ROWS);
    if (params.artifact === "vol-malfind") return HttpResponse.text(VOL_MALFIND_ROWS);
    return new HttpResponse(null, { status: 404 });
  }),

  http.get("*/v1/hosts", () => HttpResponse.json({ hosts: HOSTS })),

  http.put("*/v1/hosts/:id/roles", async ({ params, request }) => {
    const body = (await request.json()) as { roles: string[]; note?: string };
    record("PUT", `/v1/hosts/${params.id}/roles`, body);
    const base = HOSTS.find((host) => host.host_id === params.id) ?? HOSTS[0];
    return HttpResponse.json({
      ...base,
      manual_roles: body.roles,
      effective_roles: body.roles,
      role_source: "manual",
      role_revision: base.role_revision + 1,
      applied_role_revision: base.role_revision,
      manual_note: body.note ?? "",
      manual_updated_at: new Date().toISOString(),
    });
  }),

  http.delete("*/v1/hosts/:id/roles", ({ params }) => {
    record("DELETE", `/v1/hosts/${params.id}/roles`);
    const base = HOSTS.find((host) => host.host_id === params.id) ?? HOSTS[0];
    return HttpResponse.json({
      ...base,
      manual_roles: undefined,
      effective_roles: base.auto_roles.map((role) => role.role),
      role_source: "auto",
      role_revision: base.role_revision + 1,
      applied_role_revision: base.role_revision,
    });
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

  http.post("*/v1/jobs/:id/volatility", ({ params }) => {
    record("POST", `/v1/jobs/${params.id}/volatility`);
    return HttpResponse.json({ ...MEMORY_JOB, volatility_status: "running" }, { status: 202 });
  }),
];

export const server = setupServer(...handlers);
