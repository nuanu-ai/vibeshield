export interface GitHubRepoReference {
  owner: string;
  repo: string;
  type: "github";
  url: string;
}

export interface ParseGitHubRepoSuccess {
  repo: GitHubRepoReference;
  success: true;
}

export interface ParseGitHubRepoFailure {
  success: false;
  userMessage: string;
}

export type ParseGitHubRepoResult = ParseGitHubRepoSuccess | ParseGitHubRepoFailure;

const scopeError =
  "VibeShield accepts only GitHub repository URLs like https://github.com/owner/repo. " +
  "Local paths, archives, malformed URLs, and non-GitHub sources are out of scope.";

const segmentPattern = /^[A-Za-z0-9_.-]+$/;

export function parseGitHubRepoUrl(input: string): ParseGitHubRepoResult {
  if (looksLikeArchive(input)) {
    return { success: false, userMessage: scopeError };
  }

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return { success: false, userMessage: scopeError };
  }

  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.toLowerCase() !== "github.com" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    return { success: false, userMessage: scopeError };
  }

  const segments = parsed.pathname.split("/").filter(Boolean);
  if (segments.length !== 2) {
    return { success: false, userMessage: scopeError };
  }

  const [owner, rawRepo] = segments;
  const repo = rawRepo?.endsWith(".git") === true ? rawRepo.slice(0, -4) : rawRepo;

  if (
    owner === undefined ||
    repo === undefined ||
    owner.length === 0 ||
    repo.length === 0 ||
    !segmentPattern.test(owner) ||
    !segmentPattern.test(repo)
  ) {
    return { success: false, userMessage: scopeError };
  }

  return {
    repo: {
      owner,
      repo,
      type: "github",
      url: `https://github.com/${owner}/${repo}`,
    },
    success: true,
  };
}

function looksLikeArchive(input: string): boolean {
  return /(?:^|[/.])(?:zip|tar|tgz|tar\.gz)$/i.test(input) || input.includes("/archive/");
}
