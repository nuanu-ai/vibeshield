import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const extractorPath = path.join(process.cwd(), "toolchain/vibeshield-joern-extract.mjs");

describe("vibeshield-joern-extract flows", () => {
  it("extracts bounded framework-input flow seeds without joern-slice", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vibeshield-extractor-test-"));
    const binDir = path.join(dir, "bin");
    const outPath = path.join(dir, "flows.json");
    const callsPath = path.join(dir, "joern-calls.log");
    await mkdir(binDir, { recursive: true });
    await writeFile(
      path.join(binDir, "joern"),
      [
        "#!/bin/sh",
        `printf '%s\\n' "$*" >> ${shellQuote(callsPath)}`,
        "out=''",
        "prev=''",
        'for arg in "$@"; do',
        "  if [ \"$prev\" = '--param' ]; then",
        '    case "$arg" in outFile=*) out="$(printf %s "$arg" | sed s/^outFile=//)" ;; esac',
        "  fi",
        '  prev="$arg"',
        "done",
        'if [ -z "$out" ]; then echo missing outFile >&2; exit 2; fi',
        `cat > "$out" <<'EOF'
PARAM	${enc("src/server.ts::program:handler")}	${enc("handler")}	${enc("/work/source/src/server.ts")}	12		${enc("req")}	${enc("Request")}	12	9
PARAM	${enc("src/server.ts::program:helper")}	${enc("helper")}	${enc("/work/source/src/server.ts")}	30		${enc("value")}	${enc("string")}	30	4
EOF`,
      ].join("\n"),
      { mode: 0o755 },
    );

    await execFileAsync(
      process.execPath,
      [
        extractorPath,
        "--kind",
        "flows",
        "--cpg",
        "/work/vibeshield/app.cpg.bin",
        "--source-root",
        "/work/source",
        "-o",
        outPath,
      ],
      {
        env: {
          ...process.env,
          PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ""}`,
          TMPDIR: dir,
        },
      },
    );

    const calls = await readFile(callsPath, "utf8");
    const parsed = JSON.parse(await readFile(outPath, "utf8")) as unknown;
    expect(calls).toContain("--script");
    expect(calls).not.toContain("joern-slice");
    expect(parsed).toEqual([
      {
        flows: [
          {
            label: "METHOD_PARAMETER_IN",
            tags: "framework-input",
            parentFileName: "src/server.ts",
            parentMethodName: "handler",
            lineNumber: 12,
            name: "req",
            code: "req",
          },
        ],
      },
    ]);
  });
});

describe("vibeshield-joern-extract component usage", () => {
  it("enriches entity methods with bounded source blocks", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vibeshield-extractor-test-"));
    const binDir = path.join(dir, "bin");
    const sourceRoot = path.join(dir, "source");
    const outPath = path.join(dir, "entities.json");
    const appPath = path.join(sourceRoot, "app.py");
    await mkdir(binDir, { recursive: true });
    await mkdir(sourceRoot, { recursive: true });
    await writeFile(
      appPath,
      [
        "from flask import Flask",
        "app = Flask(__name__)",
        "@app.route('/welcome2/<string:name>')",
        "def welcome2(name):",
        "    data = 'Welcome ' + name",
        "    return data",
        "",
        "def unrelated():",
        "    return 'ok'",
      ].join("\n"),
    );
    await writeFile(
      path.join(binDir, "joern"),
      [
        "#!/bin/sh",
        "out=''",
        "prev=''",
        'for arg in "$@"; do',
        "  if [ \"$prev\" = '--param' ]; then",
        '    case "$arg" in outFile=*) out="$(printf %s "$arg" | sed s/^outFile=//)" ;; esac',
        "  fi",
        '  prev="$arg"',
        "done",
        'if [ -z "$out" ]; then echo missing outFile >&2; exit 2; fi',
        `cat > "$out" <<'EOF'
METHOD	${enc("app.py:<module>.welcome2")}	${enc("py")}	${enc(appPath)}	4	1	${enc("py")}	${enc("name,,4,14")}	${enc(" ")}
EOF`,
      ].join("\n"),
      { mode: 0o755 },
    );

    await execFileAsync(
      process.execPath,
      [
        extractorPath,
        "--kind",
        "entities",
        "--cpg",
        "/work/vibeshield/app.cpg.bin",
        "--source-root",
        sourceRoot,
        "-o",
        outPath,
      ],
      {
        env: {
          ...process.env,
          PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ""}`,
          TMPDIR: dir,
        },
      },
    );

    const parsed = JSON.parse(await readFile(outPath, "utf8")) as {
      readonly objectSlices: ReadonlyArray<{
        readonly code: string;
        readonly boundary?: { readonly routeOrName?: string };
      }>;
    };
    expect(parsed.objectSlices[0]?.code).toContain("data = 'Welcome ' + name");
    expect(parsed.objectSlices[0]?.code).toContain("return data");
    expect(parsed.objectSlices[0]?.code).not.toContain("def unrelated");
    expect(parsed.objectSlices[0]?.boundary?.routeOrName).toBe("/welcome2/<string:name>");
  });

  it("does not infer JavaScript web boundaries from setup-only route registration", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vibeshield-extractor-test-"));
    const binDir = path.join(dir, "bin");
    const sourceRoot = path.join(dir, "source");
    const sourceDir = path.join(sourceRoot, "src");
    const outPath = path.join(dir, "entities.json");
    const serverPath = path.join(sourceDir, "server.ts");
    await mkdir(binDir, { recursive: true });
    await mkdir(sourceDir, { recursive: true });
    await writeFile(
      serverPath,
      [
        "export function configureApp(app, seq) {",
        "  app.use('/api', handler)",
        "}",
        "",
        "export function handler(req, res) {",
        "  return res.send(req.query.name)",
        "}",
        "",
        "app.get('/profile', handler)",
      ].join("\n"),
    );
    await writeFile(
      path.join(binDir, "joern"),
      [
        "#!/bin/sh",
        "out=''",
        "prev=''",
        'for arg in "$@"; do',
        "  if [ \"$prev\" = '--param' ]; then",
        '    case "$arg" in outFile=*) out="$(printf %s "$arg" | sed s/^outFile=//)" ;; esac',
        "  fi",
        '  prev="$arg"',
        "done",
        'if [ -z "$out" ]; then echo missing outFile >&2; exit 2; fi',
        `cat > "$out" <<'EOF'
METHOD	${enc("src/server.ts::program:configureApp")}	${enc("configureApp")}	${enc(serverPath)}	1	1	${enc("configureApp")}	${enc([param("app"), param("seq")].join(";"))}	${enc(" ")}
METHOD	${enc("src/server.ts::program:handler")}	${enc("handler")}	${enc(serverPath)}	5	1	${enc("handler")}	${enc([param("req", "express.Request"), param("res", "express.Response")].join(";"))}	${enc(" ")}
CALL	${enc("src/server.ts::program:configureApp")}	${enc("app.use")}	${enc("express.Application.use")}	${enc("app.use('/api', handler)")}	2	3
EOF`,
      ].join("\n"),
      { mode: 0o755 },
    );

    await execFileAsync(
      process.execPath,
      [
        extractorPath,
        "--kind",
        "entities",
        "--cpg",
        "/work/vibeshield/app.cpg.bin",
        "--source-root",
        sourceRoot,
        "-o",
        outPath,
      ],
      {
        env: {
          ...process.env,
          PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ""}`,
          TMPDIR: dir,
        },
      },
    );

    const parsed = JSON.parse(await readFile(outPath, "utf8")) as {
      readonly objectSlices: ReadonlyArray<{
        readonly fullName?: string;
        readonly boundary?: { readonly routeOrName?: string };
      }>;
    };
    const setup = parsed.objectSlices.find(
      (slice) => slice.fullName === "src/server.ts::program:configureApp",
    );
    const handler = parsed.objectSlices.find(
      (slice) => slice.fullName === "src/server.ts::program:handler",
    );
    expect(setup?.boundary).toBeUndefined();
    expect(handler?.boundary?.routeOrName).toBe("handler");
  });

  it("extracts deterministic package import observations from source files", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vibeshield-extractor-test-"));
    const binDir = path.join(dir, "bin");
    const sourceRoot = path.join(dir, "source");
    const sourceDir = path.join(sourceRoot, "src");
    const outPath = path.join(dir, "component-usage.json");
    await mkdir(binDir, { recursive: true });
    await mkdir(sourceDir, { recursive: true });
    await writeFile(
      path.join(sourceDir, "app.ts"),
      [
        "import express from 'express';",
        "import scoped from '@scope/pkg/subpath';",
        "import local from './local';",
        "const jwt = require('jsonwebtoken');",
        "export function handler() { return express(); }",
      ].join("\n"),
    );
    await writeFile(
      path.join(binDir, "joern"),
      [
        "#!/bin/sh",
        "out=''",
        "prev=''",
        'for arg in "$@"; do',
        "  if [ \"$prev\" = '--param' ]; then",
        '    case "$arg" in outFile=*) out="$(printf %s "$arg" | sed s/^outFile=//)" ;; esac',
        "  fi",
        '  prev="$arg"',
        "done",
        'if [ -z "$out" ]; then echo missing outFile >&2; exit 2; fi',
        `cat > "$out" <<'EOF'
METHOD	${enc("src/app.ts::program")}	${enc("<global>")}	${enc(`${sourceRoot}/src/app.ts`)}	1	1	${enc("program")}		
EOF`,
      ].join("\n"),
      { mode: 0o755 },
    );

    await execFileAsync(
      process.execPath,
      [
        extractorPath,
        "--kind",
        "component_usage",
        "--cpg",
        "/work/vibeshield/app.cpg.bin",
        "--source-root",
        sourceRoot,
        "-o",
        outPath,
      ],
      {
        env: {
          ...process.env,
          PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ""}`,
          TMPDIR: dir,
        },
      },
    );

    const parsed = JSON.parse(await readFile(outPath, "utf8")) as {
      readonly componentUsages: ReadonlyArray<unknown>;
    };
    expect(parsed.componentUsages).toEqual([
      {
        packageName: "express",
        repoPath: "src/app.ts",
        usageKind: "imported",
        lineRange: { startLine: 1, endLine: 1 },
      },
      {
        packageName: "@scope/pkg",
        repoPath: "src/app.ts",
        usageKind: "imported",
        lineRange: { startLine: 2, endLine: 2 },
      },
      {
        packageName: "jsonwebtoken",
        repoPath: "src/app.ts",
        usageKind: "imported",
        lineRange: { startLine: 4, endLine: 4 },
      },
    ]);
  });
});

function enc(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

function param(name: string, typeFullName = ""): string {
  return [enc(name), typeFullName === "" ? "" : enc(typeFullName), "", ""].join(",");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}
