import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { environment, isDevelopment } from "../../src/environment";

const savedLocation = (globalThis as any).location;
const savedEnv = process.env.NODE_ENV;

beforeEach(() => {
  // clear any cached decisions
  environment.clearCache();
  delete (globalThis as any).location;
  process.env.NODE_ENV = savedEnv;
});

afterEach(() => {
  environment.clearCache();
  // restore
  (globalThis as any).location = savedLocation;
  process.env.NODE_ENV = savedEnv;
});

describe("environment utils", () => {
  it("detects private 172 ranges correctly", () => {
    // Ensure process.env does not short-circuit browser detection
    delete process.env.NODE_ENV;
  (globalThis as any).location = { hostname: "172.16.0.1" };
    environment.clearCache();
    expect(environment.isDevelopment).toBe(true);

    (globalThis as any).location = { hostname: "172.31.255.255" };
    environment.clearCache();
    expect(environment.isDevelopment).toBe(true);

    (globalThis as any).location = { hostname: "172.32.0.1" };
    environment.clearCache();
    expect(environment.isDevelopment).toBe(false);
  });

  it("recognizes common dev hostnames and prefixes/suffixes", () => {
    const cases = [
      "localhost",
      "127.0.0.1",
      "[::1]",
      "",
      "example.local",
      "site.test",
      "192.168.1.5",
      "10.5.6.7",
    ];
    // ensure NODE_ENV not set so hostname checks are used
    delete process.env.NODE_ENV;
    for (const host of cases) {
      (globalThis as any).location = { hostname: host };
      environment.clearCache();
      expect(environment.isDevelopment, `host ${host}`).toBe(true);
    }
  });

  it("respects NODE_ENV in Node environments", () => {
    // Simulate Node env
    process.env.NODE_ENV = "development";
    environment.clearCache();
    expect(environment.isDevelopment).toBe(true);

    process.env.NODE_ENV = "test";
    environment.clearCache();
    expect(environment.isDevelopment).toBe(true);

    process.env.NODE_ENV = "production";
    environment.clearCache();
    expect(environment.isDevelopment).toBe(false);
  });

  it("allows explicitly setting environment and clears cache", () => {
    environment.setExplicitEnv("development");
    expect(environment.isDevelopment).toBe(true);
    environment.setExplicitEnv("production");
    expect(environment.isDevelopment).toBe(false);
    // clear explicit env
    environment.clearCache();
    // after clearing explicit env behavior falls back
  });

  it("isDevelopment helper mirrors environment.isDevelopment", () => {
    delete process.env.NODE_ENV;
    (globalThis as any).location = { hostname: "localhost" };
    environment.clearCache();
    expect(isDevelopment()).toBe(environment.isDevelopment);
  });
});
