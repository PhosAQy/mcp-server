import { afterEach, describe, expect, it, vi } from "vitest";

import { loadConfig } from "./config.js";

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  vi.unstubAllEnvs();
});

describe("loadConfig", () => {
  it("requires DEMOX_SITE_URL", () => {
    vi.stubEnv("DEMOX_SITE_URL", "");
    vi.stubEnv("DEMOX_API_URL", "https://api.demox.site");

    expect(() => loadConfig()).toThrow("Missing required environment variable: DEMOX_SITE_URL");
  });

  it("uses DEMOX_API_URL as the default SCF and website API URL", () => {
    vi.stubEnv("DEMOX_SITE_URL", "https://demox.site/");
    vi.stubEnv("DEMOX_API_URL", "https://api.demox.site/");
    vi.stubEnv("DEMOX_CLOUD_FUNCTION_URL", "");
    vi.stubEnv("DEMOX_WEBSITE_API_URL", "");

    expect(loadConfig()).toMatchObject({
      siteUrl: "https://demox.site",
      apiBase: "https://demox.site",
      cloudFunctionUrl: "https://api.demox.site",
      websiteApiUrl: "https://api.demox.site",
    });
  });
});
