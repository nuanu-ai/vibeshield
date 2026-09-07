FROM node:24-trixie

ARG GITLEAKS_VERSION=8.30.1
ARG JOERN_VERSION=4.0.565
ARG ASTGEN_VERSION=1.0.14

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl git openjdk-21-jre-headless python3 python3-pip tar unzip \
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

RUN curl -fL --retry 5 --retry-delay 5 --retry-all-errors \
    "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-cli.zip" \
    -o /var/tmp/joern-cli.zip \
  && unzip -q /var/tmp/joern-cli.zip -d /opt \
  && rm /var/tmp/joern-cli.zip \
  && mv /opt/joern-cli /opt/joern-cli.raw \
  && mkdir -p /opt/joern-cli \
  && cp -R /opt/joern-cli.raw/. /opt/joern-cli/ \
  && rm -rf /opt/joern-cli.raw \
  && find /opt/joern-cli/frontends -mindepth 1 -maxdepth 1 -type d \
    ! -name jssrc2cpg \
    ! -name javasrc2cpg \
    ! -name pysrc2cpg \
    ! -name gosrc2cpg \
    -exec rm -rf {} + \
  && rm -f \
    /opt/joern-cli/frontends/jssrc2cpg/bin/astgen/astgen-macos \
    /opt/joern-cli/frontends/jssrc2cpg/bin/astgen/astgen-macos-arm \
    /opt/joern-cli/frontends/jssrc2cpg/bin/astgen/astgen-win.exe \
  && find /opt/joern-cli -maxdepth 2 -type f -perm /111 -exec chmod +x {} \; \
  && printf '%s\n' \
    '#!/bin/sh' \
    'exec /opt/joern-cli/bin/repl-bridge -J-XX:+UseG1GC -J-XX:CompressedClassSpaceSize=128m -Dlog4j.configurationFile=/opt/joern-cli/conf/log4j2.xml -J-XX:+UseStringDeduplication "$@"' \
    > /usr/local/bin/joern \
  && printf '%s\n' \
    '#!/bin/sh' \
    'exec /opt/joern-cli/bin/joern-parse -J-XX:+UseG1GC -J-XX:CompressedClassSpaceSize=128m -Dlog4j.configurationFile=/opt/joern-cli/conf/log4j2.xml "$@"' \
    > /usr/local/bin/joern-parse \
  && chmod +x /usr/local/bin/joern /usr/local/bin/joern-parse \
  && npm install -g "@appthreat/astgen@${ASTGEN_VERSION}" \
  && mv /usr/local/bin/astgen /usr/local/bin/astgen-real \
  && printf '%s\n' \
    '#!/bin/sh' \
    'if [ -z "${ASTGEN_CONCURRENCY:-}" ]; then export ASTGEN_CONCURRENCY=1; fi' \
    'if [ -z "${NODE_OPTIONS:-}" ]; then export NODE_OPTIONS="--max-old-space-size=1536 --expose-gc"; fi' \
    'exec /usr/local/bin/astgen-real --no-tsTypes "$@"' \
    > /usr/local/bin/astgen \
  && chmod +x /usr/local/bin/astgen \
  && mkdir -p /work \
  && ln -sf /usr/local/bin/astgen /work/astgen \
  && java -version \
  && test -x /opt/joern-cli/joern \
  && test -x /opt/joern-cli/joern-parse \
  && joern-parse --help >/tmp/joern-parse-help.txt \
  && test -x /usr/local/bin/astgen \
  && test -x /usr/local/bin/astgen-real

RUN printf '%s\n' \
    '#!/bin/bash' \
    'set -euo pipefail' \
    'out=""' \
    'input=""' \
    'while [ "$#" -gt 0 ]; do' \
    '  case "$1" in' \
    '    generate)' \
    '      ;;' \
    '    -i|--input)' \
    '      shift' \
    '      input="${1:-}"' \
    '      ;;' \
    '    -o|--output)' \
    '      shift' \
    '      out="${1:-}"' \
    '      ;;' \
    '    *)' \
    '      if [ -z "$input" ]; then input="$1"; fi' \
    '      ;;' \
    '  esac' \
    '  shift || true' \
    'done' \
    'if [ -z "$input" ] || [ -z "$out" ]; then' \
    '  echo "usage: go2cpg.sh [-o <output>] [generate] <input-dir>" >&2' \
    '  exit 2' \
    'fi' \
    'exec /opt/joern-cli/gosrc2cpg -o "$out" "$input"' \
    > /opt/joern-cli/go2cpg.sh \
  && printf '%s\n' \
    '#!/bin/bash' \
    'set -euo pipefail' \
    'out=""' \
    'input=""' \
    'while [ "$#" -gt 0 ]; do' \
    '  case "$1" in' \
    '    i)' \
    '      shift' \
    '      input="${1:-}"' \
    '      ;;' \
    '    -i|--input)' \
    '      shift' \
    '      input="${1:-}"' \
    '      ;;' \
    '    -o|--output)' \
    '      shift' \
    '      out="${1:-}"' \
    '      ;;' \
    '    *)' \
    '      if [ -z "$input" ]; then input="$1"; fi' \
    '      ;;' \
    '  esac' \
    '  shift || true' \
    'done' \
    'if [ -z "$input" ] || [ -z "$out" ]; then' \
    '  echo "usage: py2cpg.sh i <input-dir> -o <output>" >&2' \
    '  exit 2' \
    'fi' \
    'exec /opt/joern-cli/pysrc2cpg -o "$out" "$input"' \
    > /opt/joern-cli/py2cpg.sh \
  && chmod +x /opt/joern-cli/go2cpg.sh /opt/joern-cli/py2cpg.sh \
  && test -x /opt/joern-cli/py2cpg.sh \
  && test -x /opt/joern-cli/go2cpg.sh

COPY vibeshield-joern-extract.mjs /usr/local/bin/vibeshield-joern-extract
COPY vibeshield-osv-scan.mjs /usr/local/bin/vibeshield-osv-scan
RUN chmod +x /usr/local/bin/vibeshield-joern-extract /usr/local/bin/vibeshield-osv-scan \
  && vibeshield-joern-extract --help >/tmp/vibeshield-joern-extract-help.txt \
  && vibeshield-osv-scan --help >/tmp/vibeshield-osv-scan-help.txt

RUN curl -fsSL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin \
  && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin \
  && curl -fsSL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash \
    | bash -s -- latest /usr/local/bin \
  && python3 -m pip install --no-cache-dir --break-system-packages zizmor \
  && syft version \
  && trivy --version \
  && actionlint -version \
  && zizmor --version

# OpenGrep 1.25.0 release assets, pinned by upstream SHA-256 digest.
RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) asset="opengrep_manylinux_x86"; digest="9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33" ;; \
    arm64) asset="opengrep_manylinux_aarch64"; digest="fd40124272d006082a5594b19aecee07b01dd50933d8add7a4fd5c557d2be5f6" ;; \
    *) exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v1.25.0/${asset}" -o /usr/local/bin/opengrep \
  && printf '%s  %s\n' "$digest" /usr/local/bin/opengrep | sha256sum -c - \
  && chmod 755 /usr/local/bin/opengrep \
  && mkdir -p /opt/vibeshield/opengrep-home \
  && test "$(HOME=/opt/vibeshield/opengrep-home opengrep --version)" = "1.25.0"

WORKDIR /work

# Official OSV-Scanner v2.3.8, release assets pinned by upstream SHA-256.
RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) digest="bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc" ;; \
    arm64) digest="8158b18edd2d03b1a30d905ca91b032bc62262167be8f206c27114f08823e27c" ;; \
    *) exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_linux_${arch}" -o /usr/local/bin/osv-scanner \
  && printf '%s  %s\n' "$digest" /usr/local/bin/osv-scanner | sha256sum -c - \
  && chmod 755 /usr/local/bin/osv-scanner \
  && osv-scanner --version

COPY osv.mjs /usr/local/bin/vibeshield-osv
RUN mkdir -p /opt/vibeshield \
  && touch /opt/vibeshield/osv.toml \
  && chmod 644 /opt/vibeshield/osv.toml

# Public-web acquisition and file-only, redacted scanner exports.
COPY acquire.mjs /usr/local/bin/vibeshield-acquire
COPY export-results.mjs /usr/local/bin/export-results.mjs
RUN ln -s /usr/local/bin/export-results.mjs /usr/local/bin/vibeshield-export-results \
  && mkdir -p /opt/vibeshield \
  && printf '[extend]\nuseDefault = true\n' > /opt/vibeshield/gitleaks.toml \
  && touch /opt/vibeshield/gitleaks.ignore \
  && chmod 644 /opt/vibeshield/gitleaks.toml /opt/vibeshield/gitleaks.ignore

COPY rules /opt/vibeshield/rules
COPY opengrep.mjs /usr/local/bin/vibeshield-opengrep
RUN touch /opt/vibeshield/opengrep.ignore \
  && printf '{}\n' > /opt/vibeshield/opengrep-settings.yml \
  && chmod 644 /opt/vibeshield/opengrep.ignore /opt/vibeshield/opengrep-settings.yml
