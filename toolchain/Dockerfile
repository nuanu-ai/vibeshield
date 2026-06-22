FROM node:24-bookworm

ARG GITLEAKS_VERSION=8.30.1

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
