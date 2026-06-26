import { describe, expect, it } from "vitest";
import { parseScanArgs } from "../src/application/scan-args.js";

describe("scan argument parsing", () => {
  it("accepts deep mode before or after the source", () => {
    expect(parseScanArgs(["--deep", "./app"])).toEqual({
      sourceArg: "./app",
      deep: true,
      modelMode: "auto",
    });
    expect(parseScanArgs(["https://github.com/owner/repo", "--deep"])).toEqual({
      sourceArg: "https://github.com/owner/repo",
      deep: true,
      modelMode: "auto",
    });
  });

  it("keeps quick scan as the default mode", () => {
    expect(parseScanArgs(["./app"])).toEqual({
      sourceArg: "./app",
      deep: false,
      modelMode: "auto",
    });
  });

  it("accepts catalog-only mode for deterministic benchmark runs", () => {
    expect(parseScanArgs(["--no-model", "./app", "--deep"])).toEqual({
      sourceArg: "./app",
      deep: true,
      modelMode: "off",
    });
  });

  it("rejects unknown options and extra positional arguments", () => {
    expect(() => parseScanArgs(["./app", "--json"])).toThrow("Unknown scan option: --json");
    expect(() => parseScanArgs(["./app", "./other"])).toThrow("Unexpected scan argument: ./other");
  });
});
