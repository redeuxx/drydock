# Drydock image. Five stages:
#   frontend  Node LTS: npm ci, tsc, Tailwind CLI, vendored htmx (no Node in the final image)
#   build     uv: installs the locked dependencies and drydock into /app/.venv
#   age       the age CLI and its batchpass plugin for archive encryption, checksummed
#   rclone    the rclone binary for remote storage, checksummed
#   runtime   Python slim, uid 10001, works with a read-only root filesystem
# Every base image is pinned by version and multi-arch index digest.

# FRONTEND

FROM node:24.21.0-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS frontend
WORKDIR /build
COPY package.json package-lock.json ./
# Install scripts stay off: every native tool used here ships as a prebuilt optional package.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY tools ./tools
COPY frontend ./frontend
# Tailwind scans the templates for class names.
COPY src/drydock/templates ./src/drydock/templates
RUN npm run build

# BUILD

FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /bin/uv
ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1
WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
COPY --from=frontend /build/src/drydock/static/ ./src/drydock/static/
RUN uv sync --locked --no-dev --no-editable \
 && test -s /app/.venv/lib/python3.15/site-packages/drydock/static/css/app.css \
 && test -s /app/.venv/lib/python3.15/site-packages/drydock/static/js/app.js \
 && test -s /app/.venv/lib/python3.15/site-packages/drydock/static/vendor/htmx/htmx.min.js

# AGE

# age v1.3.2 encrypts archives (see README.md). The release tarball is checked against
# the SHA-256 pinned here for each architecture; only age and age-plugin-batchpass are kept.
FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae AS age
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sum=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10 ;; \
      arm64) sum=6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4 ;; \
      *) echo "no pinned age release for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-$TARGETARCH.tar.gz"; \
    python -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], "/tmp/age.tgz")' "$url"; \
    echo "$sum  /tmp/age.tgz" | sha256sum -c -; \
    mkdir /opt/age; \
    tar -xzf /tmp/age.tgz -C /opt/age --no-same-owner --strip-components=1 age/age age/age-plugin-batchpass; \
    chmod 0755 /opt/age/age /opt/age/age-plugin-batchpass

# RCLONE

# rclone v1.75.2 runs as `rclone rcd` for remote storage (storage/rclone_rc.py). The release
# zip is checked against the SHA-256 pinned here for each architecture, copied from the
# release's SHA256SUMS (identical on downloads.rclone.org and GitHub); a mismatch fails the
# build. Only the rclone binary is kept.
FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae AS rclone
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sum=349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702 ;; \
      arm64) sum=7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10 ;; \
      *) echo "no pinned rclone release for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/rclone/rclone/releases/download/v1.75.2/rclone-v1.75.2-linux-$TARGETARCH.zip"; \
    python -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], "/tmp/rclone.zip")' "$url"; \
    echo "$sum  /tmp/rclone.zip" | sha256sum -c -; \
    mkdir /opt/rclone; \
    python -c 'import shutil, sys, zipfile; shutil.copyfileobj(zipfile.ZipFile("/tmp/rclone.zip").open(sys.argv[1]), open("/opt/rclone/rclone", "xb"))' "rclone-v1.75.2-linux-$TARGETARCH/rclone"; \
    chmod 0755 /opt/rclone/rclone

# RUNTIME

FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae AS runtime
RUN groupadd --gid 10001 drydock \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin drydock \
 && mkdir -p /data /run/drydock \
 && chown 10001:10001 /data /run/drydock \
 && chmod 0700 /data /run/drydock
COPY --from=build /app/.venv /app/.venv
COPY --from=age /opt/age /opt/age
COPY --from=rclone /opt/rclone /opt/rclone
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/data/tmp
USER 10001:10001
# Not /data: uvicorn puts its working directory on sys.path, which must not be writable.
WORKDIR /app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --start-interval=2s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4); sys.exit(0 if r.status == 200 else 1)"]
# Exec form: uvicorn is PID 1 and receives SIGTERM directly. Trusted proxies come from
# the FORWARDED_ALLOW_IPS environment variable, not from a CLI argument.
CMD ["uvicorn", "drydock.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--timeout-graceful-shutdown", "30"]
