import type { FailureCode, Issue, Report, Stage } from "../scan/contracts.js";
import type { RemediationKey } from "../scan/remediation.js";
import type { Job } from "./jobs.js";

const MAX_OPEN_JOBS = 5;

const labels: Record<Stage, string> = {
  prepare: "Set up a clean machine",
  acquire: "Copy your code over",
  gitleaks: "Look for keys and passwords",
  opengrep: "Read through your code",
  osv: "Check the packages you install",
  trivy: "Check your Docker and config files",
  zizmor: "Check your GitHub Actions",
  report: "Write up what we found",
  cleanup: "Delete the copy of your code",
};

/** One job the reader can actually do, named in their words. */
const jobs: Record<RemediationKey, { start: string; title: string; why: string }> = {
  "secret-rotation": {
    start: "Start by replacing the key that is in your code.",
    title: "A key or password is sitting in your code",
    why: "Anyone who can open this repo can copy it and use it as you. So can anyone holding an old clone, and any log that printed it.",
  },
  "dependency-upgrade": {
    start: "Start by updating the packages with known bugs.",
    title: "Packages you install have known security bugs",
    why: "These run inside your app, and the bugs are already public. The fixes are published too.",
  },
  "command-input": {
    start: "Start with the shell command built from outside input.",
    title: "Outside input helps build a shell command",
    why: "Someone can append their own command to the one you meant to run.",
  },
  "sql-input": {
    start: "Start with the database query built from outside input.",
    title: "Outside input goes straight into a database query",
    why: "Someone can change what the query does and read or delete rows you never meant to expose.",
  },
  "path-url-validation": {
    start: "Start by deciding where your server is allowed to connect.",
    title: "Your server will open whatever path or address it is handed",
    why: "Someone can point it at files or internal addresses it was never meant to reach.",
  },
  "unsafe-deserialization": {
    start: "Start with the untrusted data being turned back into objects.",
    title: "Untrusted data is turned back into objects",
    why: "Rebuilding objects from data you did not write can hand control to whoever sent it.",
  },
  "jwt-validation": {
    start: "Start by checking login tokens properly.",
    title: "Login tokens are accepted without a real check",
    why: "Someone can hand you a token they made themselves and be treated as signed in.",
  },
  "config-privilege": {
    start: "Start by taking power away from the container that doesn't need it.",
    title: "A container runs with more power than it needs",
    why: "If anything ever escapes the app, it starts out with far more access than the job requires.",
  },
  "workflow-input": {
    start: "Start with the pull request text that reaches a CI script.",
    title: "Text from a pull request lands in a GitHub Actions script",
    why: "Anyone who can open a pull request can get their own text run as a command in your CI.",
  },
  "workflow-privilege": {
    start: "Start by narrowing what your workflows are allowed to touch.",
    title: "A workflow runs with more access than it needs",
    why: "Wide workflow access is a short path from a pull request to the rest of your repo.",
  },
};

/** Publication only emits known keys; rendering still never crashes on data. */
const unknownJob = {
  start: "Start with the first item below.",
  title: "Something worth fixing",
  why: "A check matched here and we have no plain description for this one yet.",
};
function jobFor(key: RemediationKey): { start: string; title: string; why: string } {
  return jobs[key] ?? unknownJob;
}

const failureText: Record<FailureCode, string> = {
  repository_unreachable:
    "We couldn't get that repo from GitHub. Check the link. Private repos don't work yet.",
  repository_too_large: "That repo is larger than we can copy in one go.",
  took_too_long: "This one ran past the time we allow, so we stopped it.",
  environment_unavailable:
    "Our scanning machine didn't start. Nothing ran, and nothing was left behind.",
  cleanup_pending: "We're still clearing up after the last scan. Try again in a few seconds.",
  internal: "Something broke on our side before we could write anything up.",
};
export function failureMessage(failure?: FailureCode): string {
  return failure ? failureText[failure] : "";
}

function escapeHtml(value: string | number): string {
  return String(value).replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char,
  );
}
function page(title: string, body: string, progress = false): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} · VibeShield</title><link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script></head><body${progress ? " data-progress" : ""}><header><a href="/">VibeShield</a><span>For repos you didn't read line by line</span></header><main>${body}</main><footer>We never start your app, so logins, permissions and payments go untested.</footer></body></html>`;
}
function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}
function repositoryName(url: string): string {
  return url.replace(/^https:\/\/github\.com\//, "");
}

export function renderHome(error?: string): string {
  return page(
    "Check a repo",
    `<h1>Check your repo before you put it online.</h1><p class="lead">Paste a GitHub link. We copy your code onto a throwaway machine, run five checks, and give you a short list of things to fix. Each one comes with a message you can paste into your coding agent.</p>${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}<form action="/scans" method="post"><label for="repository">Your repo on GitHub</label><input id="repository" name="repository" type="url" required placeholder="https://github.com/you/your-app" autocomplete="url" aria-describedby="input-help"><p id="input-help">The main page of the repo, not a branch or a file. Usually takes 2 to 5 minutes.</p><button type="submit">Check it</button></form><section class="split"><div><h2>What we look at</h2><ul class="plain"><li>Keys and passwords left in your files, and in your last 100 commits</li><li>Code where outside input reaches something dangerous</li><li>Packages you install that have known security bugs</li><li>Docker and container settings</li><li>Your GitHub Actions workflows</li></ul></div><div><h2>What we can't see</h2><ul class="plain"><li>Your app is never started, so logins, permissions and payments go untested.</li><li>An empty result means the checks that ran found nothing. It isn't a clean bill of health.</li><li>No score and no green light to deploy. We say what we found and what we missed.</li><li>We keep nothing. Your result sits in memory for an hour, then it's gone.</li></ul></div></section><p class="quiet">One scan at a time.</p>`,
  );
}

export function renderProgress(job: Job): string {
  const done = job.stages.filter((entry) => entry.status === "completed").length;
  const headline =
    job.status === "running"
      ? `Checking ${repositoryName(job.url)}`
      : job.status === "completed"
        ? "All done"
        : "This scan stopped early";
  return page(
    "Checking your repo",
    `<h1>${escapeHtml(headline)}</h1><p class="lead" role="status" data-status>${job.status === "running" ? `${done} of ${job.stages.length} steps done` : job.status === "completed" ? "Opening your report" : "Here is what happened"}</p><p data-error role="alert">${escapeHtml(failureMessage(job.failure))}</p><button type="button" data-retry hidden>Try that again</button><ol class="stages" data-stages>${job.stages
      .map(
        (entry) =>
          `<li data-stage="${escapeHtml(entry.stage)}" data-state="${escapeHtml(entry.status)}"><strong>${escapeHtml(labels[entry.stage])}</strong><span data-stage-state>${escapeHtml(entry.message)}</span></li>`,
      )
      .join(
        "",
      )}</ol><p class="quiet">Close the tab if you like. It keeps running, and this page picks up where it left off.</p><p><a href="/">Check another repo</a></p>`,
    true,
  );
}

interface FixJob {
  readonly key: RemediationKey;
  readonly issues: Issue[];
}
function groupByFix(issues: readonly Issue[]): FixJob[] {
  const grouped = new Map<RemediationKey, Issue[]>();
  for (const issue of issues) {
    const existing = grouped.get(issue.remediationKey);
    if (existing) existing.push(issue);
    else grouped.set(issue.remediationKey, [issue]);
  }
  return [...grouped].map(([key, members]) => ({ key, issues: members }));
}
function locationsOf(job: FixJob): string[] {
  return job.issues.flatMap((issue) =>
    issue.locations.map((location) => `${location.path}:${location.line}`),
  );
}
function whereLine(job: FixJob): string {
  const places = locationsOf(job);
  const files = new Set(places.map((place) => place.slice(0, place.lastIndexOf(":"))));
  return `${plural(places.length, "place")} in ${plural(files.size, "file")}`;
}
function agentPrompt(job: FixJob, repository: string): string {
  const first = job.issues[0];
  if (!first) return "";
  return [
    `${jobFor(job.key).title} in ${repositoryName(repository)}.`,
    "",
    "Where it is:",
    ...locationsOf(job).map((place) => `  ${place}`),
    "",
    `What to change: ${first.remediation}`,
    `Then check: ${first.verification}`,
    "",
    "A scanner matched these places. Nothing was run, so confirm each one before you treat it as proven.",
  ].join("\n");
}
function fixBody(job: FixJob, repository: string): string {
  const first = job.issues[0];
  if (!first) return "";
  return `<p class="why">${escapeHtml(jobFor(job.key).why)}</p><dl class="what"><dt>What to do</dt><dd>${escapeHtml(first.remediation)}</dd><dt>Then check</dt><dd>${escapeHtml(first.verification)}</dd></dl><div class="prompt"><p class="label">Paste this to your coding agent</p><pre data-prompt tabindex="0">${escapeHtml(agentPrompt(job, repository))}</pre><button type="button" data-copy>Copy</button><span role="status" data-copy-status></span></div><details class="tech"><summary>Where exactly, and how we found it</summary><ul class="plain">${locationsOf(
    job,
  )
    .map((place) => `<li><code>${escapeHtml(place)}</code></li>`)
    .join("")}</ul><ul class="plain">${job.issues
    .flatMap((issue) => [issue.title, ...issue.evidence])
    .map((line) => `<li>${escapeHtml(line)}</li>`)
    .join("")}</ul></details>`;
}
function renderFix(job: FixJob, index: number, repository: string): string {
  const heading = `${index + 1}. ${jobFor(job.key).title}`;
  if (index < MAX_OPEN_JOBS)
    return `<article data-fix open><h2>${escapeHtml(heading)}</h2><p class="where">${escapeHtml(whereLine(job))}</p>${fixBody(job, repository)}</article>`;
  return `<article data-fix><details><summary>${escapeHtml(heading)} — ${escapeHtml(whereLine(job))}</summary>${fixBody(job, repository)}</details></article>`;
}

export function renderReport(report: Report): string {
  const fixes = groupByFix(report.issues);
  const first = fixes[0];
  const hidden = Math.max(0, fixes.length - MAX_OPEN_JOBS);
  const headline = first
    ? jobFor(first.key).start
    : report.incomplete
      ? "Scan incomplete"
      : "No important problems found by the completed checks";
  const lead = first
    ? `${plural(fixes.length, "thing")} to fix in ${escapeHtml(repositoryName(report.repository.url))}.${report.incomplete ? " Scan incomplete: some checks didn't see everything, and that's written down below." : ""}`
    : report.incomplete
      ? "Some checks didn't finish, so treat this as an unfinished picture rather than a clean result."
      : "Nothing to do from these checks. That is not the same as being safe.";
  return page(
    "What we found",
    `<p class="eyebrow">${first ? "Do this first" : "Result"}</p><h1>${escapeHtml(headline)}</h1><p class="lead">${lead}</p>${fixes
      .map((job, index) => renderFix(job, index, report.repository.url))
      .join(
        "",
      )}${hidden ? `<p class="quiet">${plural(hidden, "more job")} above, folded up.</p>` : ""}<section class="after"><h2>What we looked at</h2><p>${escapeHtml(
      coverageLine(report),
    )}</p><details class="tech"><summary>Check by check, and what we left out</summary><ul class="plain">${report.coverage
      .map(
        (entry) =>
          `<li><code>${escapeHtml(entry.scanner)} · ${escapeHtml(entry.area)}</code> ${escapeHtml(entry.status)}${entry.applicable ? "" : " · not applicable"} — ${escapeHtml(entry.reason)}</li>`,
      )
      .join(
        "",
      )}</ul><p>We looked through ${escapeHtml(plural(report.repository.history.commits, "commit"))} of history${report.repository.history.truncated ? "; anything older was not fetched" : ""}.</p><p>${escapeHtml(
      report.suppressedCount
        ? `${plural(report.suppressedCount, "other alert")} came out of these checks and did not make your list: low severity, low confidence, or a rule we have no checked fix for yet.`
        : "Nothing else was held back.",
    )}</p><p>Commit <code>${escapeHtml(report.repository.commit)}</code>, image <code>${escapeHtml(report.provenance.image)}</code>, rules <code>${escapeHtml(report.provenance.rulesRevision)}</code>.</p><ul class="plain">${Object.entries(
      report.provenance.tools,
    )
      .map(([tool, version]) => `<li>${escapeHtml(tool)} ${escapeHtml(version)}</li>`)
      .join(
        "",
      )}${report.provenance.advisoryData.map((data) => `<li>${escapeHtml(data.source)} ${escapeHtml(data.retrievedAt)}${data.revision ? ` · ${escapeHtml(data.revision)}` : ""}${data.stale ? " · stale" : ""}</li>`).join("")}</ul></details></section><section class="after"><h2>What this can't tell you</h2><ul class="plain"><li>Your app never started. Logins, permissions and payments went untested.</li><li>If one user can open another user's data, that looks like ordinary code to every check here.</li><li>We found patterns. Proving someone can actually pull one off is a separate job.</li><li>This is one commit at one moment. Nothing keeps watching after you close this page.</li></ul></section><p><a href="/">Check another repo</a></p>`,
  );
}
function coverageLine(report: Report): string {
  const limited = report.coverage.filter(
    (entry) =>
      entry.applicable &&
      (entry.status === "failed" || entry.status === "degraded" || entry.status === "skipped"),
  ).length;
  return limited
    ? `${plural(limited, "check")} couldn't see everything. The rest ran over all ${plural(report.repository.files.length, "file")} in the repo.`
    : `Every check ran over all ${plural(report.repository.files.length, "file")} in the repo.`;
}

export function renderUnavailable(): string {
  return page(
    "Nothing here",
    '<h1>This result is no longer available</h1><p class="lead">Results last an hour, and they do not survive a restart. Nothing is stored anywhere.</p><p><a href="/">Check a repo</a></p>',
  );
}
