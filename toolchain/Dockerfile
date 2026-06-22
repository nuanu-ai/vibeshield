FROM node:24-bookworm

ARG GITLEAKS_VERSION=8.30.1

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl git tar \
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

WORKDIR /work
