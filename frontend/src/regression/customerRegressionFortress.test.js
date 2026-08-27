/**
 * Customer regression fortress — source-level contracts.
 * Locks shipped promises so later agents cannot silently regress login,
 * engine scale, scan target errors, or jobs diagnostics without failing CI.
 */
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ENGINES_REGISTRY } from "../lib/enginesRegistry.js";
import { PRODUCTION_ENGINE_COUNT } from "../lib/platformScale.js";
import { boundClientId, shouldHideClientPicker } from "../lib/clientScope.js";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../..");
const frontend = resolve(here, "../..");

function readRepo(rel) {
  return readFileSync(resolve(repo, rel), "utf8");
}

function readFront(rel) {
  return readFileSync(resolve(frontend, rel), "utf8");
}

describe("auth/login surface lock", () => {
  it("SPA basename is /command-center and login is the only auth route", () => {
    const main = readFront("src/main.jsx");
    expect(main).toContain('basename="/command-center"');
    expect(main).not.toMatch(/basename=["']\/["']/);

    const app = readFront("src/TacticalApp.jsx");
    expect(app).toMatch(/path=["']login["']/);
    expect(app).not.toMatch(/path=["']signin["']/);
    expect(app).not.toMatch(/path=["']auth["']/);
    expect(app).toMatch(/path=["']\*["']/);
    expect(app).toMatch(/<NotFound\s*\/>/);
  });

  it("Login.jsx is the live cockpit (563 + CyberLiveBackdrop), not a stub", () => {
    const login = readFront("src/components/cockpit/Login.jsx");
    expect(login).toMatch(/CyberLiveBackdrop/);
    expect(login).toMatch(/PRODUCTION_ENGINE_COUNT/);
    expect(login).not.toMatch(/254 production engines/);
    expect(login).not.toMatch(/auth-mesh-drift/);
    expect(login).toMatch(/motion\.form/);
    expect(login).toMatch(/auth\.authenticate/);
  });

  it("legacy /login /signin /auth are not mounted on the Axum server", () => {
    const serve = readRepo("fingerprint_engine/src/http/serve.rs");
    expect(serve).toMatch(/nest_service\("\/command-center"/);
    expect(serve).not.toMatch(/\.route\("\/login"/);
    expect(serve).not.toMatch(/\.route\("\/signin"/);
    expect(serve).not.toMatch(/\.route\("\/auth"/);
  });

  it("live backdrop CSS is imported into the global stylesheet", () => {
    const css = readFront("src/index.css");
    expect(css).toMatch(/cyber-live-backdrop\.css/);
    const backdrop = readFront("src/styles/cyber-live-backdrop.css");
    expect(backdrop).toMatch(/\.wm-cyber-backdrop/);
    expect(backdrop).toMatch(/@keyframes wm-cbg-sweep-run/);
  });
});

describe("engine count lock 563 vs registry", () => {
  it("frontend scale, registry length, and Login copy stay at 563", () => {
    expect(PRODUCTION_ENGINE_COUNT).toBe(563);
    expect(ENGINES_REGISTRY).toHaveLength(563);
    const ids = ENGINES_REGISTRY.map((e) => e.id);
    expect(new Set(ids).size).toBe(563);
    expect(readFront("src/components/cockpit/Login.jsx")).toMatch(/PRODUCTION_ENGINE_COUNT/);
  });
});

describe("client scope lock", () => {
  it("boundClientId never honors a spoofed override when the JWT is bound", () => {
    const session = {
      ok: true,
      role: "client",
      assigned_client_id: 42,
      client_picker_hidden: true,
      is_client_user: true,
    };
    const catalog = [
      { id: 42, name: "Bound Co" },
      { id: 99, name: "Other Corp" },
    ];
    expect(boundClientId(session, catalog, 99)).toBe(42);
    expect(boundClientId(session, catalog, null)).toBe(42);
    expect(shouldHideClientPicker(session, catalog)).toBe(true);
  });

  it("ScopedClientControl is the only CommandBar client picker", () => {
    const bar = readFront("src/components/CommandBar.jsx");
    expect(bar).toMatch(/ScopedClientControl/);
    expect(bar).not.toMatch(/<select[^>]*name=["']client_id["']/);
  });
});

describe("scan contract — server invariant", () => {
  it("documents target_required as a stable error code, not a crash", () => {
    const routing = readRepo("fingerprint_engine/src/scan_routing.rs");
    expect(routing).toMatch(/TARGET_REQUIRED_ERROR_CODE/);
    expect(routing).toMatch(/"target_required"/);
    expect(routing).toMatch(/fn reject_empty_target/);
    const openapi = readRepo("fingerprint_engine/src/server_handlers_rest2.inc");
    expect(openapi).toMatch(/target_required/);
    expect(openapi).toMatch(/\/api\/command-center\/scan/);
  });
});

describe("jobs diagnostics contract", () => {
  it("handler JSON names redis, workers, pending_no_envelope, stuck_reason", () => {
    const jobs = readRepo("fingerprint_engine/src/server_handlers_jobs.inc");
    expect(jobs).toMatch(/"redis":/);
    expect(jobs).toMatch(/"workers":/);
    expect(jobs).toMatch(/"pending_no_envelope"/);
    expect(jobs).toMatch(/"stuck_reason":/);
  });
});

describe("RoE OT block contract", () => {
  it("OT engines return EngineResult::roe_blocked, not fake ICS hits", () => {
    const roe = readRepo("fingerprint_engine/src/critical_infra/roe.rs");
    expect(roe).toMatch(/fn blocked_engine_result/);
    expect(roe).toMatch(/EngineResult::roe_blocked/);
    expect(roe).toMatch(/would_run_if_authorized/);
    expect(roe).not.toMatch(/simulated ics|modbus holding|triton implant/i);
    const dispatch = readRepo("fingerprint_engine/src/engine_dispatch.rs");
    expect(dispatch).toMatch(/blocked_engine_result/);
  });
});
