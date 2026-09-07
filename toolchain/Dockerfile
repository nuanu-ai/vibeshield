FROM node:24.20.0-trixie@sha256:f7d34e58713740f9eef9092c0bd6ff10369d132f7238399a4b270f16d47fa608

# The immutable base and exclusive snapshot sources freeze transitive APT inputs.
# Expired snapshot dates are allowed; archive signatures and hashes stay required.
RUN printf '%s\n' \
    'Types: deb' \
    'URIs: https://snapshot.debian.org/archive/debian/20260901T000000Z/' \
    'Suites: trixie trixie-updates' \
    'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' \
    '' \
    'Types: deb' \
    'URIs: https://snapshot.debian.org/archive/debian-security/20260901T000000Z/' \
    'Suites: trixie-security' \
    'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' \
    > /etc/apt/sources.list.d/debian.sources \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    bash=5.2.37-2+b9 \
    ca-certificates=20250419 \
    curl=8.14.1-2+deb13u4 \
    git=1:2.47.3-0+deb13u1 \
    openjdk-21-jre-headless=21.0.12.1+1-1~deb13u1 \
    python3=3.13.5-1 \
    python3-pip=25.1.1+dfsg-1 \
    tar=1.35+dfsg-3.1 \
    unzip=6.0-29+deb13u1 \
  && mkdir -p /opt/vibeshield \
  && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > /opt/vibeshield/debian-packages.tsv \
  && rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) gitleaks_arch="x64"; digest="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;; \
    arm64) gitleaks_arch="arm64"; digest="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;; \
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
  esac \
  && curl -fsSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${gitleaks_arch}.tar.gz" \
    -o /tmp/gitleaks.tar.gz \
  && printf '%s  %s\n' "$digest" /tmp/gitleaks.tar.gz | sha256sum -c - \
  && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
  && rm /tmp/gitleaks.tar.gz \
  && test "$(gitleaks version)" = "8.30.1"

# astgen's lockfile verifies every npm tarball. Its postinstall downloads shfmt
# without verification, so scripts are disabled and shfmt is installed explicitly.
COPY astgen/package.json astgen/package-lock.json /opt/vibeshield/astgen/
RUN npm ci --prefix /opt/vibeshield/astgen --omit=dev --ignore-scripts --no-audit --no-fund \
  && arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) digest="43439b996942b53dfafa9b6ff084f394555d049c98fb7ec37978f7668b43e1be" ;; \
    arm64) digest="1cb7fc0ace531b907977827a0fe31f6e2595afcafe554e6d7f9d6f4470e37336" ;; \
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/mvdan/sh/releases/download/v3.2.1/shfmt_v3.2.1_linux_${arch}" -o /usr/local/bin/shfmt \
  && printf '%s  %s\n' "$digest" /usr/local/bin/shfmt | sha256sum -c - \
  && chmod 755 /usr/local/bin/shfmt \
  && test "$(shfmt -version)" = "v3.2.1"

RUN curl -fL --retry 5 --retry-delay 5 --retry-all-errors \
    "https://github.com/joernio/joern/releases/download/v4.0.565/joern-cli.zip" \
    -o /var/tmp/joern-cli.zip \
  && printf '%s  %s\n' '26f3016f749ec810434c8ccb72962eb22fec8654b72c3f4acedf962fddc634de' /var/tmp/joern-cli.zip | sha256sum -c - \
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
  && ln -s /opt/vibeshield/astgen/node_modules/.bin/astgen /usr/local/bin/astgen-real \
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

RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) syft_digest="8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"; actionlint_digest="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8" ;; \
    arm64) syft_digest="a7fd2b784e6664acd44719270574f6cd8c6864fc2b1700bf9099bd1cccda7d7f"; actionlint_digest="325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6" ;; \
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_${arch}.tar.gz" -o /tmp/syft.tar.gz \
  && printf '%s  %s\n' "$syft_digest" /tmp/syft.tar.gz | sha256sum -c - \
  && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
  && rm /tmp/syft.tar.gz \
  && curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_${arch}.tar.gz" -o /tmp/actionlint.tar.gz \
  && printf '%s  %s\n' "$actionlint_digest" /tmp/actionlint.tar.gz | sha256sum -c - \
  && tar -xzf /tmp/actionlint.tar.gz -C /usr/local/bin actionlint \
  && rm /tmp/actionlint.tar.gz \
  && syft version \
  && actionlint -version

# Official zizmor v1.30.0 immutable release archives; MIT license at the exact tag commit.
RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) asset="x86_64"; digest="ec8c95cd800845abb9bbc5f377ec7c57d2eb8e2386a00a201d3a74ee4092e5ed" ;; \
    arm64) asset="aarch64"; digest="018a024d6b6d09733b07f6ef42838d984c23ec04bc9b2acd55f7d67826aeafe5" ;; \
    *) exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/zizmorcore/zizmor/releases/download/v1.30.0/zizmor-${asset}-unknown-linux-gnu.tar.gz" -o /tmp/zizmor.tar.gz \
  && printf '%s  %s\n' "$digest" /tmp/zizmor.tar.gz | sha256sum -c - \
  && tar -xzf /tmp/zizmor.tar.gz -C /usr/local/bin zizmor \
  && rm /tmp/zizmor.tar.gz \
  && test "$(zizmor --version)" = "zizmor 1.30.0"
COPY licenses/zizmor.LICENSE /opt/vibeshield/zizmor/LICENSE
RUN printf '%s  %s\n' 'a6fd1bd18da7cec8284639d5b0d351b90934317be1b9f9ea94a077621c6f35af' /opt/vibeshield/zizmor/LICENSE | sha256sum -c -

# Official Trivy 0.72.0 release tarballs, pinned by upstream SHA-256.
RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) asset="64bit"; digest="bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea" ;; \
    arm64) asset="ARM64"; digest="2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467" ;; \
    *) exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-${asset}.tar.gz" -o /tmp/trivy.tar.gz \
  && printf '%s  %s\n' "$digest" /tmp/trivy.tar.gz | sha256sum -c - \
  && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
  && mkdir -p /opt/vibeshield/trivy \
  && tar -xzf /tmp/trivy.tar.gz -C /opt/vibeshield/trivy LICENSE \
  && rm /tmp/trivy.tar.gz \
  && trivy --version

# Official checks 2.2.0, OCI manifest sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c.
# This cache is selected explicitly. Missing/corrupt files fail before Trivy's embedded fallback.
RUN mkdir -p /opt/vibeshield/trivy/cache/policy/content \
  && curl -fsSL "https://mirror.gcr.io/v2/aquasec/trivy-checks/blobs/sha256:40a47ef8eb262c8e41d44f25c266463fff4dba9adcba12d33b93da88cbc7c80f" -o /tmp/trivy-checks.tar.gz \
  && printf '%s  %s\n' '40a47ef8eb262c8e41d44f25c266463fff4dba9adcba12d33b93da88cbc7c80f' /tmp/trivy-checks.tar.gz | sha256sum -c - \
  && tar --no-same-owner -xzf /tmp/trivy-checks.tar.gz -C /opt/vibeshield/trivy/cache/policy/content \
  && rm /tmp/trivy-checks.tar.gz \
  && printf '{"Digest":"sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c","MajorVersion":2}\n' > /opt/vibeshield/trivy/cache/policy/metadata.json \
  && printf '{}\n' > /opt/vibeshield/trivy.yaml \
  && touch /opt/vibeshield/empty.ignore
COPY trivy-manifest.json /opt/vibeshield/trivy/manifest.json
COPY licenses/trivy-checks.LICENSE /opt/vibeshield/trivy/CHECKS-LICENSE
COPY trivy.mjs /usr/local/bin/vibeshield-trivy

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
COPY zizmor.mjs /usr/local/bin/vibeshield-zizmor
RUN node /usr/local/bin/vibeshield-zizmor install-config
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

# Include reviewed notices and the exact content used to derive this image's tag.
COPY licenses /opt/vibeshield/licenses
COPY . /opt/vibeshield/build-input
RUN node /opt/vibeshield/build-input/verify.mjs
