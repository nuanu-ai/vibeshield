#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

const USAGE_KINDS = new Set(["entities", "boundaries", "call_edges", "component_usage"]);

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  printUsage();
  process.exit(0);
}

if (!isKind(args.kind) || args.cpg === undefined || args.out === undefined) {
  printUsage();
  process.exit(2);
}

const workTmp = process.env.TMPDIR ?? "/work/vibeshield/tmp";
await mkdir(workTmp, { recursive: true });
const tempRoot = await mkdtemp(path.join(workTmp, "vibeshield-joern-"));
try {
  const normalized = USAGE_KINDS.has(args.kind)
    ? await extractCpgUsages(args.cpg, tempRoot, args.sourceRoot)
    : await extractDataFlow(args.cpg, tempRoot);
  await writeFile(args.out, `${JSON.stringify(normalized)}\n`);
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--help" || value === "-h") {
      parsed.help = true;
      continue;
    }
    if (value === "--kind") {
      parsed.kind = values[++index];
      continue;
    }
    if (value === "--cpg") {
      parsed.cpg = values[++index];
      continue;
    }
    if (value === "--source-root") {
      parsed.sourceRoot = values[++index];
      continue;
    }
    if (value === "-o" || value === "--out") {
      parsed.out = values[++index];
      continue;
    }
    throw new Error(`unknown argument: ${value}`);
  }
  return parsed;
}

function printUsage() {
  process.stderr.write(
    "Usage: vibeshield-joern-extract --kind <entities|boundaries|call_edges|flows|component_usage> --cpg <cpg.bin> -o <out.json>\n",
  );
}

function isKind(value) {
  return (
    value === "entities" ||
    value === "boundaries" ||
    value === "call_edges" ||
    value === "flows" ||
    value === "component_usage"
  );
}

async function run(command, commandArgs) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, {
      stdio: "inherit",
      env: {
        ...process.env,
        TMPDIR: process.env.TMPDIR ?? "/work/vibeshield/tmp",
        TMP: process.env.TMP ?? process.env.TMPDIR ?? "/work/vibeshield/tmp",
        TEMP: process.env.TEMP ?? process.env.TMPDIR ?? "/work/vibeshield/tmp",
        JAVA_TOOL_OPTIONS:
          process.env.JAVA_TOOL_OPTIONS ?? "-Xmx3072m -Djava.io.tmpdir=/work/vibeshield/tmp",
      },
    });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} exited ${code ?? signal ?? "unknown"}`));
    });
  });
}

async function extractCpgUsages(cpgPath, tempRoot, sourceRoot) {
  const scriptPath = path.join(tempRoot, "extract.sc");
  const rawPath = path.join(tempRoot, "cpg.tsv");
  await writeFile(scriptPath, cpgUsageScript());
  await run("joern", [
    "--script",
    scriptPath,
    "--param",
    `cpgFile=${cpgPath}`,
    "--param",
    `outFile=${rawPath}`,
  ]);
  return await normalizeUsages(parseCpgTsv(await readFile(rawPath, "utf8")), sourceRoot);
}

async function extractDataFlow(cpgPath, tempRoot) {
  const scriptPath = path.join(tempRoot, "flow-seeds.sc");
  const rawPath = path.join(tempRoot, "flow-seeds.tsv");
  await writeFile(scriptPath, cpgFlowSeedScript());
  await run("joern", [
    "--script",
    scriptPath,
    "--param",
    `cpgFile=${cpgPath}`,
    "--param",
    `outFile=${rawPath}`,
  ]);
  return normalizeDataFlowSeeds(parseFlowSeedTsv(await readFile(rawPath, "utf8")));
}

async function normalizeUsages(raw, sourceRoot) {
  const sources = sourceLookup(sourceRoot);
  const sourceRoutes = routesRegisteredByCalls(raw.methods, raw.callsByParent);
  const objectSlices = [];
  for (const method of raw.methods) {
    const calls = raw.callsByParent.get(method.fullName) ?? [];
    const sourceCode = await methodSourceBlock(sources, method);
    objectSlices.push({
      code: sourceCode ?? method.code,
      fullName: method.fullName,
      fileName: sources.normalizeRepoPath(method.fileName),
      lineNumber: method.lineNumber,
      columnNumber: method.columnNumber,
      usages: calls.map((call) => ({
        targetObj: {
          label: "CALL",
          name: call.name,
          resolvedMethod: call.resolvedMethod,
          code: call.code,
          lineNumber: call.lineNumber,
          columnNumber: call.columnNumber,
        },
      })),
      ...boundaryHint(
        method,
        calls,
        sourceRoutes.get(method.fullName) ?? (await routeFromSource(sources, method)),
      ),
      parameters: method.parameters,
    });
  }
  return {
    objectSlices: objectSlices.filter(
      (item) =>
        item.fullName !== undefined && item.fileName !== undefined && item.lineNumber !== undefined,
    ),
    componentUsages: await componentUsagesFromSource(sources),
  };
}

async function componentUsagesFromSource(sources) {
  const observations = [
    ...(await jsComponentUsages(sources)),
    ...(await pythonComponentUsages(sources)),
    ...(await goComponentUsages(sources)),
    ...(await javaComponentUsages(sources)),
  ];
  const seen = new Set();
  const out = [];
  for (const observation of observations) {
    const key = [
      observation.packageName,
      observation.repoPath,
      observation.lineRange.startLine,
      observation.usageKind,
    ].join("\0");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(observation);
  }
  return out.sort(compareComponentUsageObservations);
}

async function jsComponentUsages(sources) {
  const files = [
    ...(await sources.readRepoFilesByExtension(".js")),
    ...(await sources.readRepoFilesByExtension(".jsx")),
    ...(await sources.readRepoFilesByExtension(".mjs")),
    ...(await sources.readRepoFilesByExtension(".cjs")),
    ...(await sources.readRepoFilesByExtension(".ts")),
    ...(await sources.readRepoFilesByExtension(".tsx")),
    ...(await sources.readRepoFilesByExtension(".mts")),
    ...(await sources.readRepoFilesByExtension(".cts")),
  ];
  const observations = [];
  for (const file of files) {
    const patterns = [
      /\bimport\s+(?:type\s+)?(?:[^'"]+\s+from\s+)?["']([^"']+)["']/g,
      /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
      /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
    ];
    for (const pattern of patterns) {
      for (const match of file.text.matchAll(pattern)) {
        const packageName = packageNameFromJsSpecifier(match[1]);
        if (packageName === undefined) {
          continue;
        }
        observations.push(componentUsage(packageName, file.repoPath, file.text, match.index));
      }
    }
  }
  return observations;
}

async function pythonComponentUsages(sources) {
  const files = await sources.readRepoFilesByExtension(".py");
  const observations = [];
  for (const file of files) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((line, index) => {
      const importMatch = line.match(/^\s*import\s+(.+)$/);
      if (importMatch !== null) {
        for (const imported of importMatch[1].split(",")) {
          const packageName = packageNameFromPythonImport(imported);
          if (packageName !== undefined) {
            observations.push(componentUsageAtLine(packageName, file.repoPath, index + 1));
          }
        }
      }
      const fromMatch = line.match(/^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+/);
      const fromPackage = packageNameFromPythonImport(fromMatch?.[1]);
      if (fromPackage !== undefined) {
        observations.push(componentUsageAtLine(fromPackage, file.repoPath, index + 1));
      }
    });
  }
  return observations;
}

async function goComponentUsages(sources) {
  const files = await sources.readRepoFilesByExtension(".go");
  const observations = [];
  for (const file of files) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const match of line.matchAll(/(?:import\s+)?(?:[\w.]+\s+)?["`]([^"`]+)["`]/g)) {
        const packageName = packageNameFromGoImport(match[1]);
        if (packageName !== undefined) {
          observations.push(componentUsageAtLine(packageName, file.repoPath, index + 1));
        }
      }
    });
  }
  return observations;
}

async function javaComponentUsages(sources) {
  const files = await sources.readRepoFilesByExtension(".java");
  const observations = [];
  for (const file of files) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((line, index) => {
      const match = line.match(
        /^\s*import\s+(?:static\s+)?([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+)(?:\.\*)?\s*;/,
      );
      const packageName = packageNameFromJavaImport(match?.[1]);
      if (packageName !== undefined) {
        observations.push(componentUsageAtLine(packageName, file.repoPath, index + 1));
      }
    });
  }
  return observations;
}

async function methodSourceBlock(sources, method) {
  const repoPath = sources.normalizeRepoPath(method.fileName);
  const lineNumber = optionalPositiveInteger(method.lineNumber);
  if (repoPath === undefined || lineNumber === undefined) {
    return undefined;
  }
  const text = await sources.readRepoFile(repoPath);
  if (text === undefined) {
    return undefined;
  }
  const lines = text.split(/\r?\n/);
  const startIndex = lineNumber - 1;
  if (startIndex < 0 || startIndex >= lines.length) {
    return undefined;
  }
  const block = repoPath.endsWith(".py")
    ? pythonMethodSourceBlock(lines, startIndex)
    : boundedSourceBlock(lines, startIndex, 24);
  const source = block.join("\n").trimEnd();
  return source === "" ? undefined : source;
}

function pythonMethodSourceBlock(lines, startIndex) {
  const first = lines[startIndex] ?? "";
  const baseIndent = indentation(first);
  const block = [];
  for (let index = startIndex; index < Math.min(lines.length, startIndex + 80); index += 1) {
    const line = lines[index] ?? "";
    if (
      index > startIndex &&
      line.trim() !== "" &&
      indentation(line) <= baseIndent &&
      /^(?:@|async\s+def\b|def\b|class\b)/.test(line.trim())
    ) {
      break;
    }
    block.push(line);
  }
  return block;
}

function boundedSourceBlock(lines, startIndex, limit) {
  return lines.slice(startIndex, Math.min(lines.length, startIndex + limit));
}

function indentation(line) {
  return line.match(/^\s*/)?.[0]?.length ?? 0;
}

function componentUsage(packageName, repoPath, text, index) {
  return componentUsageAtLine(packageName, repoPath, lineNumberAt(text, index));
}

function componentUsageAtLine(packageName, repoPath, lineNumber) {
  return {
    packageName,
    repoPath,
    usageKind: "imported",
    lineRange: { startLine: lineNumber, endLine: lineNumber },
  };
}

function packageNameFromJsSpecifier(value) {
  const specifier = string(value);
  if (
    specifier === undefined ||
    specifier.startsWith(".") ||
    specifier.startsWith("/") ||
    specifier.startsWith("node:") ||
    /^[a-z][a-z0-9+.-]*:/i.test(specifier)
  ) {
    return undefined;
  }
  const parts = specifier.split("/").filter(Boolean);
  if (parts.length === 0) {
    return undefined;
  }
  return parts[0].startsWith("@") && parts.length > 1 ? `${parts[0]}/${parts[1]}` : parts[0];
}

function packageNameFromPythonImport(value) {
  const raw = string(value)
    ?.split(/\s+as\s+/i)[0]
    ?.trim();
  if (raw === undefined || raw.startsWith(".")) {
    return undefined;
  }
  return raw.split(".")[0];
}

function packageNameFromGoImport(value) {
  const raw = string(value);
  if (raw === undefined || raw.startsWith(".") || !raw.includes(".")) {
    return undefined;
  }
  return raw;
}

function packageNameFromJavaImport(value) {
  const raw = string(value);
  if (raw === undefined || raw.startsWith("java.") || raw.startsWith("javax.")) {
    return undefined;
  }
  const parts = raw.split(".").filter(Boolean);
  return parts.length < 2 ? undefined : parts.slice(0, Math.min(3, parts.length)).join(".");
}

function lineNumberAt(text, index) {
  if (typeof index !== "number" || index <= 0) {
    return 1;
  }
  return text.slice(0, index).split(/\r?\n/).length;
}

function boundaryHint(method, calls, sourceRoute) {
  const code = string(method.code) ?? "";
  const route =
    routeFromAnnotations(method.annotations) ??
    routeFromCode(method, code) ??
    sourceRoute ??
    routeFromCalls(method, calls) ??
    routeFromRequestParameter(method);
  if (route === undefined) {
    return {};
  }
  return {
    boundary: {
      boundaryType: route.boundaryType,
      routeOrName: route.routeOrName,
      method: route.method,
      sourceName: route.sourceName,
    },
  };
}

async function routeFromSource(sources, method) {
  return (
    (await routeFromPythonSource(sources, method)) ?? (await routeFromGoSource(sources, method))
  );
}

function routesRegisteredByCalls(methods, callsByParent) {
  const methodsByFullName = new Map();
  const methodsByName = new Map();
  for (const method of methods) {
    if (!isIndexableMethod(method)) {
      continue;
    }
    methodsByFullName.set(method.fullName, method);
    for (const name of methodLookupNames(method)) {
      const current = methodsByName.get(name) ?? [];
      if (!current.some((candidate) => candidate.fullName === method.fullName)) {
        current.push(method);
      }
      methodsByName.set(name, current);
    }
  }

  const routesByMethod = new Map();
  for (const calls of callsByParent.values()) {
    for (const call of calls) {
      const registration = routeRegistrationFromCall(call);
      if (registration === undefined) {
        continue;
      }
      for (const handlerName of registration.handlerNames) {
        const targets = routeHandlerTargets(
          handlerName,
          call,
          calls,
          methodsByFullName,
          methodsByName,
        );
        if (targets.length !== 1) {
          continue;
        }
        const target = targets[0];
        if (target?.fullName === undefined || routesByMethod.has(target.fullName)) {
          continue;
        }
        routesByMethod.set(target.fullName, {
          boundaryType: registration.boundaryType,
          routeOrName: registration.routeOrName,
          method: registration.method,
          sourceName: "request",
        });
      }
    }
  }
  return routesByMethod;
}

function isIndexableMethod(method) {
  return string(method.fullName) !== undefined && normalizeRepoPath(method.fileName) !== undefined;
}

function methodLookupNames(method) {
  return unique([string(method.name), symbolFromFullName(method.fullName)].filter(Boolean));
}

function symbolFromFullName(value) {
  const fullName = string(value);
  if (fullName === undefined) {
    return undefined;
  }
  return string(fullName.split(":").at(-1));
}

function routeHandlerTargets(
  handlerName,
  routeCall,
  siblingCalls,
  methodsByFullName,
  methodsByName,
) {
  const exactTargets = uniqueMethods(
    siblingCalls
      .filter((call) => call.lineNumber === routeCall.lineNumber)
      .filter((call) => callMatchesHandlerName(call, handlerName))
      .map((call) => methodsByFullName.get(string(call.resolvedMethod)))
      .filter(Boolean),
  );
  return exactTargets.length > 0 ? exactTargets : (methodsByName.get(handlerName) ?? []);
}

function callMatchesHandlerName(call, handlerName) {
  return (
    string(call.name) === handlerName || symbolFromFullName(call.resolvedMethod) === handlerName
  );
}

function routeRegistrationFromCall(call) {
  const code = string(call.code);
  if (code === undefined) {
    return undefined;
  }
  const method = routeMethodFromCall(call, code);
  if (method === undefined) {
    return undefined;
  }
  const route = firstRouteArgumentForMethod(code, method);
  if (route === undefined) {
    return undefined;
  }
  const handlerNames = unique(
    callArguments(code)
      .slice(1)
      .flatMap(handlerNamesFromRouteArgument)
      .filter((name) => !isIgnoredRouteHandlerName(name)),
  );
  if (handlerNames.length === 0) {
    return undefined;
  }
  return {
    boundaryType: "javascript-web",
    routeOrName: route.routeOrName,
    method,
    handlerNames,
  };
}

function routeMethodFromCall(call, code) {
  const method =
    routeMethodFromName(call.name) ??
    routeMethodFromName(call.resolvedMethod) ??
    routeMethodFromCode(code);
  if (method === undefined) {
    return undefined;
  }
  const routeCall = firstRouteArgumentForMethod(code, method);
  if (routeCall === undefined) {
    return undefined;
  }
  const resolvedMethod = (string(call.resolvedMethod) ?? "").toLowerCase();
  if (/\bexpress\b|router|express\.application/.test(resolvedMethod)) {
    return method;
  }
  return isLikelyJavaScriptRouteReceiver(routeCall.receiver) ? method : undefined;
}

function routeMethodFromName(value) {
  const name = string(value)?.toLowerCase();
  const method = name?.split(/[.:#]/).at(-1);
  return isJavaScriptRouteMethod(method) ? method.toUpperCase() : undefined;
}

function routeMethodFromCode(code) {
  const match = code.match(/\.\s*(get|post|put|patch|delete|all|use)\s*\(/i);
  const method = match?.[1]?.toLowerCase();
  return isJavaScriptRouteMethod(method) ? method.toUpperCase() : undefined;
}

function firstRouteArgumentForMethod(code, method) {
  const methodPattern = escapeRegExp(method.toLowerCase());
  const match = code.match(
    new RegExp(
      String.raw`\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*${methodPattern}\s*\(\s*(?:["'\`]([^"'\`]+)["'\`]|\[\s*["'\`]([^"'\`]+)["'\`])`,
      "i",
    ),
  );
  const receiver = match?.[1];
  const routeOrName = match?.[2] ?? match?.[3];
  if (receiver === undefined || routeOrName === undefined || match.index === undefined) {
    return undefined;
  }
  return {
    receiver,
    routeOrName,
    endIndex: match.index + match[0].length,
  };
}

function isLikelyJavaScriptRouteReceiver(receiver) {
  const lastSegment = receiver.split(".").at(-1)?.toLowerCase();
  return (
    lastSegment === "app" ||
    lastSegment === "application" ||
    lastSegment === "server" ||
    lastSegment === "router" ||
    lastSegment?.endsWith("router") === true ||
    lastSegment?.endsWith("routes") === true
  );
}

function isJavaScriptRouteMethod(value) {
  return (
    value === "get" ||
    value === "post" ||
    value === "put" ||
    value === "patch" ||
    value === "delete" ||
    value === "all" ||
    value === "use"
  );
}

function callArguments(code) {
  const open = code.indexOf("(");
  const close = code.lastIndexOf(")");
  if (open < 0 || close <= open) {
    return [];
  }
  const args = [];
  let current = "";
  let depth = 0;
  let quote;
  let escaped = false;
  for (const char of code.slice(open + 1, close)) {
    if (quote !== undefined) {
      current += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = undefined;
      }
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      current += char;
      continue;
    }
    if (char === "(" || char === "[" || char === "{") {
      depth += 1;
      current += char;
      continue;
    }
    if (char === ")" || char === "]" || char === "}") {
      depth = Math.max(0, depth - 1);
      current += char;
      continue;
    }
    if (char === "," && depth === 0) {
      args.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim() !== "") {
    args.push(current.trim());
  }
  return args;
}

function handlerNamesFromRouteArgument(argument) {
  const trimmed = argument.trim();
  if (trimmed === "" || /^["'`]/.test(trimmed) || trimmed.startsWith("{")) {
    return [];
  }
  const direct = trimmed.match(/^([A-Za-z_$][\w$]*)$/)?.[1];
  if (direct !== undefined) {
    return [direct];
  }
  const asyncWrapped = trimmed.match(
    /\basyncHandler\s*\(\s*(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*\(/,
  )?.[1];
  if (asyncWrapped !== undefined) {
    return [asyncWrapped];
  }
  const factoryCall = trimmed.match(/^(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*\(/)?.[1];
  return factoryCall === undefined ? [] : [factoryCall];
}

async function routeFromPythonSource(sources, method) {
  const repoPath = sources.normalizeRepoPath(method.fileName);
  if (repoPath === undefined || !repoPath.endsWith(".py")) {
    return undefined;
  }
  const lineNumber = optionalPositiveInteger(method.lineNumber);
  if (lineNumber === undefined) {
    return undefined;
  }
  const text = await sources.readRepoFile(repoPath);
  if (text === undefined) {
    return undefined;
  }
  const lines = text.split(/\r?\n/);
  const defIndex = lineNumber - 1;
  const decoratorBlock = lines.slice(Math.max(0, defIndex - 12), defIndex).join("\n");
  const route = lastMatch(
    decoratorBlock.matchAll(
      /@[\w.]+\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']([\s\S]*?)\)/g,
    ),
  );
  if (route === undefined) {
    return undefined;
  }
  return {
    boundaryType: "python-web",
    routeOrName: route[2],
    method: pythonHttpMethod(route[1], route[3] ?? ""),
    sourceName: "request",
  };
}

async function routeFromGoSource(sources, method) {
  const repoPath = sources.normalizeRepoPath(method.fileName);
  const methodName = string(method.name);
  if (repoPath === undefined || !repoPath.endsWith(".go") || methodName === undefined) {
    return undefined;
  }

  const registration = await goRouteRegistrationForMethod(sources, methodName);
  if (registration === undefined) {
    return undefined;
  }
  return {
    boundaryType: "go-web",
    routeOrName: registration.route,
    method: registration.method,
    sourceName: "request",
  };
}

async function goRouteRegistrationForMethod(sources, methodName) {
  const escapedName = escapeRegExp(methodName);
  const files = await sources.readRepoFilesByExtension(".go");
  for (const file of files) {
    const routePattern = String.raw`["'\`]([^"'\`]+)["'\`]`;
    const handleFunc = new RegExp(
      String.raw`\b(?:[\w.]+\.)?(HandleFunc|Handle)\s*\(\s*${routePattern}\s*,\s*${escapedName}\b`,
      "m",
    );
    const routerMethod = new RegExp(
      String.raw`\b[\w.]+\.(GET|POST|PUT|PATCH|DELETE|ANY|Any|HandleFunc)\s*\(\s*${routePattern}\s*,\s*${escapedName}\b`,
      "m",
    );
    const handleMatch = file.text.match(handleFunc);
    if (handleMatch !== null) {
      return { route: handleMatch[2], method: "ANY" };
    }
    const routerMatch = file.text.match(routerMethod);
    if (routerMatch !== null) {
      return { route: routerMatch[2], method: routerMatch[1].toUpperCase() };
    }
  }
  return undefined;
}

function pythonHttpMethod(decoratorMethod, argsText) {
  if (decoratorMethod !== "route") {
    return decoratorMethod.toUpperCase();
  }
  const explicit = argsText.match(/\bmethods\s*=\s*\[?\s*["']([A-Z]+)["']/i);
  return explicit?.[1]?.toUpperCase() ?? "ANY";
}

function routeFromCode(method, code) {
  const spring = code.match(
    /@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)[\s\S]*?(?:\)|$)/m,
  );
  if (spring !== null) {
    return springRoute(spring[1], spring[0]);
  }

  const python = code.match(
    /@(app|router|blueprint)\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/m,
  );
  if (python !== null) {
    return {
      boundaryType: "python-web",
      routeOrName: python[3],
      method: python[2].toUpperCase(),
      sourceName: "request",
    };
  }

  const js = hasRequestParameter(method)
    ? code.match(/\b(?:app|router)\.(get|post|put|patch|delete|all|use)\s*\(\s*["']([^"']+)["']/m)
    : null;
  if (js !== null) {
    return {
      boundaryType: "javascript-web",
      routeOrName: js[2],
      method: js[1].toUpperCase(),
      sourceName: "request",
    };
  }

  return undefined;
}

function routeFromAnnotations(annotations) {
  for (const annotation of annotations ?? []) {
    const name = string(annotation.name);
    const code = string(annotation.code);
    if (
      name === undefined ||
      code === undefined ||
      !/(?:Get|Post|Put|Patch|Delete|Request)Mapping$/.test(name)
    ) {
      continue;
    }
    return springRoute(name, code);
  }
  return undefined;
}

function springRoute(annotation, code) {
  return {
    boundaryType: "spring",
    routeOrName: springRoutePath(annotation, code),
    method: httpMethodFromSpringAnnotation(annotation, code),
    sourceName: "request",
  };
}

function springRoutePath(annotation, code) {
  const direct = code.match(/@\w+Mapping\s*\(\s*(?:"([^"]+)"|'([^']+)')/m);
  const named = code.match(/\b(?:path|value)\s*=\s*(?:\{\s*)?(?:"([^"]+)"|'([^']+)')/m);
  return direct?.[1] ?? direct?.[2] ?? named?.[1] ?? named?.[2] ?? annotation;
}

function routeFromCalls(method, calls) {
  if ((method.fileName ?? "").endsWith(".java")) {
    return undefined;
  }
  if (!hasRequestParameter(method)) {
    return undefined;
  }
  const routeCall = calls.find((call) => {
    const code = (string(call.code) ?? "").toLowerCase();
    return /\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\(/.test(code);
  });
  if (routeCall === undefined) {
    return undefined;
  }
  const name = (
    string(routeCall.name) ??
    string(routeCall.resolvedMethod) ??
    "route"
  ).toLowerCase();
  return {
    boundaryType: "web-route",
    routeOrName: string(routeCall.code) ?? string(routeCall.name) ?? "route",
    method: name.split(".").at(-1)?.toUpperCase(),
    sourceName: "request",
  };
}

function routeFromRequestParameter(method) {
  if ((method.fileName ?? "").endsWith(".java")) {
    return undefined;
  }
  if (method.fullName.endsWith("::program")) {
    return undefined;
  }
  const requestParameter = method.parameters.find((parameter) => isRequestParameter(parameter));
  if (requestParameter === undefined) {
    return undefined;
  }
  return {
    boundaryType: "framework-input",
    routeOrName: method.name ?? method.fullName.split(":").at(-1) ?? method.fullName,
    sourceName: requestParameter.name ?? "request",
  };
}

function hasRequestParameter(method) {
  return method.parameters.some((parameter) => isRequestParameter(parameter));
}

function isIgnoredRouteHandlerName(name) {
  return (
    name === "app" ||
    name === "router" ||
    name === "req" ||
    name === "request" ||
    name === "res" ||
    name === "response" ||
    name === "next" ||
    name === "utils" ||
    name === "asyncHandler" ||
    name === "single" ||
    name === "array" ||
    name === "fields"
  );
}

function isRequestParameter(parameter) {
  const name = (parameter.name ?? "").toLowerCase();
  const type = (parameter.typeFullName ?? "").toLowerCase();
  return (
    name === "req" ||
    name === "request" ||
    name === "httprequest" ||
    type.includes("request") ||
    type.includes("httpservletrequest") ||
    type.includes("gin.context") ||
    type.includes("fiber.ctx") ||
    type.includes("echo.context") ||
    type.includes("fastapi") ||
    type.includes("flask") ||
    type.includes("django")
  );
}

function httpMethodFromSpringAnnotation(annotation, code = "") {
  switch (annotation) {
    case "GetMapping":
      return "GET";
    case "PostMapping":
      return "POST";
    case "PutMapping":
      return "PUT";
    case "PatchMapping":
      return "PATCH";
    case "DeleteMapping":
      return "DELETE";
    default:
      if (code.includes("RequestMethod.GET") && !code.includes("RequestMethod.POST")) {
        return "GET";
      }
      if (code.includes("RequestMethod.POST") && !code.includes("RequestMethod.GET")) {
        return "POST";
      }
      return "ANY";
  }
}

function normalizeDataFlowSeeds(raw) {
  const records = [];
  for (const seed of raw.seeds) {
    const repoPath = normalizeRepoPath(seed.fileName);
    const lineNumber = seed.parameterLineNumber ?? seed.methodLineNumber;
    const parameter = {
      name: seed.parameterName,
      typeFullName: seed.parameterTypeFullName,
      lineNumber,
      columnNumber: seed.parameterColumnNumber,
    };
    if (
      repoPath === undefined ||
      lineNumber === undefined ||
      seed.methodName === undefined ||
      !isRequestParameter(parameter)
    ) {
      continue;
    }
    records.push({
      flows: [
        {
          label: "METHOD_PARAMETER_IN",
          tags: "framework-input",
          parentFileName: repoPath,
          parentMethodName: seed.methodName,
          parentClassName: seed.parentClassName,
          lineNumber,
          name: seed.parameterName ?? seed.parameterTypeFullName ?? "request",
          code: seed.parameterName ?? seed.parameterTypeFullName ?? "request",
        },
      ],
    });
  }
  return records.sort(compareFlowSeedRecords);
}

function normalizeRepoPath(value) {
  if (value === undefined) {
    return undefined;
  }
  if (value === "<empty>") {
    return undefined;
  }
  const marker = "/work/source/";
  const index = value.indexOf(marker);
  const normalized = index >= 0 ? value.slice(index + marker.length) : value;
  return normalized.replace(/^\.\//, "");
}

function sourceLookup(sourceRoot) {
  const root = path.resolve(sourceRoot ?? "/work/source");
  const fileCache = new Map();
  const filesByExtension = new Map();
  return {
    normalizeRepoPath(value) {
      return normalizeRepoPathForRoot(root, value);
    },
    async readRepoFile(repoPath) {
      const normalized = normalizeRepoPath(repoPath);
      if (normalized === undefined) {
        return undefined;
      }
      if (fileCache.has(normalized)) {
        return fileCache.get(normalized);
      }
      const sourcePath = safeSourcePath(root, normalized);
      if (sourcePath === undefined) {
        fileCache.set(normalized, undefined);
        return undefined;
      }
      try {
        const text = await readFile(sourcePath, "utf8");
        fileCache.set(normalized, text);
        return text;
      } catch {
        fileCache.set(normalized, undefined);
        return undefined;
      }
    },
    async readRepoFilesByExtension(extension) {
      if (filesByExtension.has(extension)) {
        return filesByExtension.get(extension);
      }
      const files = [];
      for (const repoPath of await listRepoFiles(root, root, extension)) {
        const text = await this.readRepoFile(repoPath);
        if (text !== undefined) {
          files.push({ repoPath, text });
        }
      }
      filesByExtension.set(extension, files);
      return files;
    },
  };
}

function normalizeRepoPathForRoot(root, value) {
  const normalized = normalizeRepoPath(value);
  if (normalized === undefined) {
    return undefined;
  }
  if (value !== undefined && path.isAbsolute(value)) {
    const resolved = path.resolve(value);
    if (resolved === root || resolved.startsWith(`${root}${path.sep}`)) {
      return path.relative(root, resolved).split(path.sep).join("/");
    }
  }
  return normalized;
}

async function listRepoFiles(root, dir, extension) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const paths = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "vendor") {
        continue;
      }
      paths.push(...(await listRepoFiles(root, absolutePath, extension)));
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith(extension)) {
      continue;
    }
    const repoPath = path.relative(root, absolutePath).split(path.sep).join("/");
    if (repoPath !== "" && !repoPath.startsWith("..")) {
      paths.push(repoPath);
    }
  }
  return paths.sort();
}

function safeSourcePath(root, repoPath) {
  if (path.isAbsolute(repoPath)) {
    return undefined;
  }
  const resolved = path.resolve(root, repoPath);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`) ? resolved : undefined;
}

function lastMatch(matches) {
  let last;
  for (const match of matches) {
    last = match;
  }
  return last;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseCpgTsv(text) {
  const methods = [];
  const callsByParent = new Map();
  const seenMethodKeys = new Set();
  const seenCallKeys = new Set();
  for (const line of text.split("\n")) {
    if (line.trim() === "") {
      continue;
    }
    const fields = line.split("\t");
    const recordType = fields[0];
    if (recordType === "METHOD") {
      const method = {
        fullName: decode(fields[1]),
        name: decode(fields[2]),
        fileName: decode(fields[3]),
        lineNumber: optionalPositiveInteger(fields[4]),
        columnNumber: optionalPositiveInteger(fields[5]),
        code: decode(fields[6]),
        parameters: parseParameters(decode(fields[7])),
        annotations: parseAnnotations(decode(fields[8])),
      };
      const key = [method.fullName, method.fileName, method.lineNumber].join("\0");
      if (!seenMethodKeys.has(key)) {
        methods.push(method);
        seenMethodKeys.add(key);
      }
      continue;
    }
    if (recordType === "CALL") {
      const call = {
        parentFullName: decode(fields[1]),
        name: decode(fields[2]),
        resolvedMethod: decode(fields[3]),
        code: decode(fields[4]),
        lineNumber: optionalPositiveInteger(fields[5]),
        columnNumber: optionalPositiveInteger(fields[6]),
      };
      if (
        call.parentFullName === undefined ||
        (call.name === undefined && call.resolvedMethod === undefined)
      ) {
        continue;
      }
      const key = [
        call.parentFullName,
        call.name,
        call.resolvedMethod,
        call.lineNumber,
        call.columnNumber,
      ].join("\0");
      if (seenCallKeys.has(key)) {
        continue;
      }
      seenCallKeys.add(key);
      const current = callsByParent.get(call.parentFullName) ?? [];
      current.push(call);
      callsByParent.set(call.parentFullName, current);
    }
  }
  methods.sort(compareMethods);
  for (const [parent, calls] of callsByParent) {
    callsByParent.set(parent, calls.sort(compareCalls));
  }
  return { methods, callsByParent };
}

function parseFlowSeedTsv(text) {
  const seeds = [];
  const seen = new Set();
  for (const line of text.split("\n")) {
    if (line.trim() === "") {
      continue;
    }
    const fields = line.split("\t");
    if (fields[0] !== "PARAM") {
      continue;
    }
    const seed = {
      methodFullName: decode(fields[1]),
      methodName: decode(fields[2]),
      fileName: decode(fields[3]),
      methodLineNumber: optionalPositiveInteger(fields[4]),
      parentClassName: decode(fields[5]),
      parameterName: decode(fields[6]),
      parameterTypeFullName: decode(fields[7]),
      parameterLineNumber: optionalPositiveInteger(fields[8]),
      parameterColumnNumber: optionalPositiveInteger(fields[9]),
    };
    const key = [
      seed.methodFullName,
      seed.fileName,
      seed.methodLineNumber,
      seed.parameterName,
      seed.parameterTypeFullName,
      seed.parameterLineNumber,
    ].join("\0");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    seeds.push(seed);
  }
  return { seeds: seeds.sort(compareFlowSeeds) };
}

function parseParameters(value) {
  return string(value) === undefined
    ? []
    : value
        .split(";")
        .filter((item) => item.length > 0)
        .map((item) => {
          const fields = item.split(",");
          return {
            name: decode(fields[0]),
            typeFullName: decode(fields[1]),
            lineNumber: optionalPositiveInteger(fields[2]),
            columnNumber: optionalPositiveInteger(fields[3]),
          };
        });
}

function parseAnnotations(value) {
  return string(value) === undefined
    ? []
    : value
        .split(";")
        .filter((item) => item.length > 0)
        .map((item) => {
          const fields = item.split(",");
          return {
            name: decode(fields[0]),
            code: decode(fields[1]),
            fullName: decode(fields[2]),
          };
        });
}

function decode(value) {
  if (value === undefined || value === "") {
    return undefined;
  }
  const decoded = Buffer.from(value, "base64").toString("utf8");
  return decoded.trim() === "" || decoded === "<empty>" ? undefined : decoded;
}

function optionalPositiveInteger(value) {
  if (value === undefined || value === "") {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function compareMethods(a, b) {
  return (
    (a.fileName ?? "").localeCompare(b.fileName ?? "") ||
    (a.lineNumber ?? 0) - (b.lineNumber ?? 0) ||
    (a.fullName ?? "").localeCompare(b.fullName ?? "")
  );
}

function compareCalls(a, b) {
  return (
    (a.lineNumber ?? 0) - (b.lineNumber ?? 0) ||
    (a.columnNumber ?? 0) - (b.columnNumber ?? 0) ||
    (a.name ?? "").localeCompare(b.name ?? "") ||
    (a.resolvedMethod ?? "").localeCompare(b.resolvedMethod ?? "")
  );
}

function compareFlowSeeds(a, b) {
  return (
    (a.fileName ?? "").localeCompare(b.fileName ?? "") ||
    (a.methodLineNumber ?? 0) - (b.methodLineNumber ?? 0) ||
    (a.methodFullName ?? "").localeCompare(b.methodFullName ?? "") ||
    (a.parameterLineNumber ?? 0) - (b.parameterLineNumber ?? 0) ||
    (a.parameterName ?? "").localeCompare(b.parameterName ?? "")
  );
}

function compareFlowSeedRecords(a, b) {
  const left = a.flows[0] ?? {};
  const right = b.flows[0] ?? {};
  return (
    (left.parentFileName ?? "").localeCompare(right.parentFileName ?? "") ||
    (left.lineNumber ?? 0) - (right.lineNumber ?? 0) ||
    (left.parentMethodName ?? "").localeCompare(right.parentMethodName ?? "") ||
    (left.name ?? "").localeCompare(right.name ?? "")
  );
}

function compareComponentUsageObservations(a, b) {
  return (
    a.repoPath.localeCompare(b.repoPath) ||
    a.lineRange.startLine - b.lineRange.startLine ||
    a.packageName.localeCompare(b.packageName) ||
    a.usageKind.localeCompare(b.usageKind)
  );
}

function unique(values) {
  return [...new Set(values)];
}

function uniqueMethods(values) {
  const byFullName = new Map();
  for (const value of values) {
    if (value?.fullName !== undefined) {
      byFullName.set(value.fullName, value);
    }
  }
  return [...byFullName.values()];
}

function string(value) {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function cpgUsageScript() {
  return `
import io.shiftleft.semanticcpg.language._
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.util.Base64

@main def main(cpgFile: String, outFile: String) = {
  importCpg(cpgFile, enhance = false)

  def enc(value: String): String =
    Base64.getEncoder.encodeToString(Option(value).getOrElse("").getBytes(StandardCharsets.UTF_8))

  def optInt(value: Option[Int]): String =
    value.map(_.toString).getOrElse("")

  val writer = Files.newBufferedWriter(Paths.get(outFile), StandardCharsets.UTF_8)
  try {
    cpg.method.foreach { method =>
      val params = method.parameter.map { parameter =>
        Seq(
          enc(parameter.name),
          enc(parameter.typeFullName),
          optInt(parameter.lineNumber),
          optInt(parameter.columnNumber)
        ).mkString(",")
      }.l.mkString(";")

      val annotations = method.annotation.map { annotation =>
        Seq(
          enc(annotation.name),
          enc(annotation.code),
          enc(annotation.fullName)
        ).mkString(",")
      }.l.mkString(";")

      writer.write(
        Seq(
          "METHOD",
          enc(method.fullName),
          enc(method.name),
          enc(method.filename),
          optInt(method.lineNumber),
          optInt(method.columnNumber),
          enc(method.code),
          enc(params),
          enc(annotations)
        ).mkString("\\t")
      )
      writer.newLine()
    }

    cpg.call.foreach { call =>
      writer.write(
        Seq(
          "CALL",
          enc(call.method.fullName),
          enc(call.name),
          enc(call.methodFullName),
          enc(call.code),
          optInt(call.lineNumber),
          optInt(call.columnNumber)
        ).mkString("\\t")
      )
      writer.newLine()
    }
  } finally {
    writer.close()
  }
}
`;
}

function cpgFlowSeedScript() {
  return `
import io.shiftleft.semanticcpg.language._
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.util.Base64

@main def main(cpgFile: String, outFile: String) = {
  importCpg(cpgFile, enhance = false)

  def enc(value: String): String =
    Base64.getEncoder.encodeToString(Option(value).getOrElse("").getBytes(StandardCharsets.UTF_8))

  def optInt(value: Option[Int]): String =
    value.map(_.toString).getOrElse("")

  val writer = Files.newBufferedWriter(Paths.get(outFile), StandardCharsets.UTF_8)
  try {
    cpg.method.foreach { method =>
      method.parameter.foreach { parameter =>
        writer.write(
          Seq(
            "PARAM",
            enc(method.fullName),
            enc(method.name),
            enc(method.filename),
            optInt(method.lineNumber),
            enc(""),
            enc(parameter.name),
            enc(parameter.typeFullName),
            optInt(parameter.lineNumber),
            optInt(parameter.columnNumber)
          ).mkString("\\t")
        )
        writer.newLine()
      }
    }
  } finally {
    writer.close()
  }
}
`;
}
