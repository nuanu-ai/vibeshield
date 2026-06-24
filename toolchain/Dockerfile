FROM node:24-bookworm

ARG GITLEAKS_VERSION=8.30.1
ARG ATOM_VERSION=2.5.6
ARG ATOM_PARSETOOLS_VERSION=1.2.2

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl git python3 python3-pip tar \
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

RUN arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
    amd64) atom_asset="atom-amd64"; atom_sha256="d7e4f790d20ad7e72d3e62cd3d8ace54a7601b06a98e0f25a043eb8ccb9c181f" ;; \
    arm64) atom_asset="atom-arm64"; atom_sha256="19aa672a4ea429c230447aa993ef87eef4effca018b5f33702a7f480bffbf730" ;; \
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
  esac \
  && curl -fsSL \
    "https://github.com/AppThreat/atom/releases/download/v${ATOM_VERSION}/${atom_asset}" \
    -o /usr/local/bin/atom \
  && echo "${atom_sha256}  /usr/local/bin/atom" | sha256sum -c - \
  && chmod +x /usr/local/bin/atom \
  && npm install -g "@appthreat/atom-parsetools@${ATOM_PARSETOOLS_VERSION}" \
  && atom --help >/tmp/atom-help.txt \
  && command -v astgen

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
