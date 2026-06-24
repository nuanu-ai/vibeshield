FROM node:24-trixie

ARG GITLEAKS_VERSION=8.30.1
ARG ATOM_VERSION=2.5.6
ARG ATOM_PARSETOOLS_VERSION=1.2.2

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl git openjdk-21-jre-headless python3 python3-pip tar \
  && rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) gitleaks_arch="x64" ;; \
    arm64) gitleaks_arch="arm64" ;; \
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
  esac \
  && curl -fsSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" \
    -o /tmp/gitleaks.tar.gz \
  && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
  && rm /tmp/gitleaks.tar.gz \
  && gitleaks version

RUN npm install -g "@appthreat/atom@${ATOM_VERSION}" "@appthreat/atom-parsetools@${ATOM_PARSETOOLS_VERSION}" \
  && mv /usr/local/bin/atom /usr/local/bin/atom-real \
  && mv /usr/local/bin/astgen /usr/local/bin/astgen-real \
  && printf '%s\n' \
    '#!/bin/sh' \
    'if [ -z "${ASTGEN_CONCURRENCY:-}" ]; then export ASTGEN_CONCURRENCY=1; fi' \
    'if [ -z "${NODE_OPTIONS:-}" ]; then export NODE_OPTIONS="--max-old-space-size=1536 --expose-gc"; fi' \
    'exec /usr/local/bin/astgen-real --no-tsTypes "$@"' \
    > /usr/local/bin/astgen \
  && printf '%s\n' \
    '#!/bin/sh' \
    'tmpdir="${VIBESHIELD_ATOM_TMPDIR:-${TMPDIR:-/work/vibeshield/tmp}}"' \
    'mkdir -p "$tmpdir"' \
    'export TMPDIR="$tmpdir"' \
    'export TMP="${TMP:-$tmpdir}"' \
    'export TEMP="${TEMP:-$tmpdir}"' \
    'if [ -z "${ASTGEN_CONCURRENCY:-}" ]; then export ASTGEN_CONCURRENCY=1; fi' \
    'if [ -z "${NODE_OPTIONS:-}" ]; then export NODE_OPTIONS="--max-old-space-size=1536 --expose-gc"; fi' \
    'if [ -z "${JAVA_TOOL_OPTIONS:-}" ]; then export JAVA_TOOL_OPTIONS="-Xmx3072m -Djava.io.tmpdir=$tmpdir"; fi' \
    'exec /usr/local/bin/atom-real "$@"' \
    > /usr/local/bin/atom \
  && chmod +x /usr/local/bin/atom /usr/local/bin/astgen \
  && java -version \
  && atom --help >/tmp/atom-help.txt \
  && astgen --help >/tmp/astgen-help.txt

RUN curl -fsSL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin \
  && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin \
  && curl -fsSL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash \
    | bash -s -- latest /usr/local/bin \
  && curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash \
  && ln -sf /root/.opengrep/cli/latest/opengrep /usr/local/bin/opengrep \
  && python3 -m pip install --no-cache-dir --break-system-packages zizmor \
  && syft version \
  && trivy --version \
  && actionlint -version \
  && opengrep --version \
  && zizmor --version

WORKDIR /work
