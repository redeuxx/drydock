# Development

The app needs Linux (`fcntl`, unix sockets), so Python always runs in containers. Node 24 LTS on the host builds the client code and stylesheet.

## Dev loop (Windows or Linux)

```sh
npm ci --ignore-scripts
npm run build                      # TypeScript, Tailwind CSS + daisyUI, vendored htmx
mkdir -p secrets && <generate a key into secrets/drydock_secret_key as in the README>
docker compose -f compose.dev.yaml up --build
```

`src/` is bind-mounted into the container and uvicorn reloads when Python files change. On Windows the repo sits on NTFS, where inotify events do not reach the Linux VM, so the dev compose file sets `WATCHFILES_FORCE_POLLING=true`. Run `npm run watch:css` and `npm run watch:js` on the host while editing templates or `frontend/`.

## Tests

```sh
# Ruff and pytest, in Linux
docker compose -f compose.test.yaml run --rm tests
docker compose -f compose.test.yaml down --volumes

# CSP smoke test: headless Chromium against the production image
docker compose -f compose.test.yaml up --build --abort-on-container-exit --exit-code-from smoke app smoke
docker compose -f compose.test.yaml down

# TypeScript type checks
npm run check
```

The suite runs on 8 pytest-xdist workers (`-n 8 --dist loadgroup`, in compose.test.yaml): about 8 minutes instead of 27 serially. Tests that use the sshhost, over SSH or through its dind daemon, carry `on_sshhost` (tests/docker_support.py; tests/conftest.py adds it to every dind test) and run on one worker, one at a time: each SSH test replaces its authorized_keys, one restarts sshd, and a restore there locks other workers' helpers that mount what it writes. A test that makes Docker objects names them uniquely and cleans up only its own; parametrized IDs must not be random, or the workers collect different tests. A single test runs serially: `docker compose -f compose.test.yaml run --rm tests uv run --no-sync pytest -k csrf`.

There is no CI on push: the tests, audits and smoke test run locally before a push. The only workflow, `.forgejo/workflows/release.yml`, runs on a release tag (see Releases). The repository is pushed to GitHub too, without any workflow.

The suite runs on the image's Python by default. To run it on another supported Python, set `DRYDOCK_TEST_PYTHON_IMAGE` to a digest-pinned `python:X.Y-slim` image.

Audits before a release, all on the commit to be tagged, right before tagging:

```sh
docker compose -f compose.test.yaml run --rm --no-deps -e HOME=/tmp -e UV_TOOL_DIR=/tmp/uv-tools tests sh -c 'uv export --locked --no-dev --no-emit-project --format requirements-txt -o /tmp/requirements.txt -q && uvx pip-audit==2.10.1 --strict --require-hashes --disable-pip --cache-dir /tmp/pip-audit-cache -r /tmp/requirements.txt'
npm audit

# Image scans with Trivy and Grype, on fresh amd64 and arm64 builds. Every one must exit 0.
# They run only here: the release workflow does not scan.
TRIVY=docker.io/aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
GRYPE=docker.io/anchore/grype:v0.121.2@sha256:6a36234da13f9faa327306ac0b3dab3405cfa2b4eb20c8f904125a8707863913
docker run --rm --privileged "$(sed -n 's/^  BINFMT: //p' .forgejo/workflows/release.yml)" --install arm64
docker build -q -t drydock:scan .
docker buildx build -q --platform linux/arm64 --load -t drydock:scan-arm64 .

# Fresh databases: Trivy reuses a cached one for up to a day. Check both were built in the last day.
docker run --rm -v drydock-trivy-cache:/cache "$TRIVY" clean --vuln-db --cache-dir /cache
docker run --rm -v drydock-trivy-cache:/cache "$TRIVY" image --download-db-only --quiet --cache-dir /cache
docker run --rm -v drydock-trivy-cache:/cache "$TRIVY" version --cache-dir /cache
docker run --rm -v drydock-grype-db:/cache -e GRYPE_DB_CACHE_DIR=/cache "$GRYPE" db update
docker run --rm -v drydock-grype-db:/cache -e GRYPE_DB_CACHE_DIR=/cache "$GRYPE" db status

for image in drydock:scan drydock:scan-arm64; do
  docker run --rm -i -v /var/run/docker.sock:/var/run/docker.sock -v drydock-trivy-cache:/cache --entrypoint sh "$TRIVY" -c "cat > /tmp/ignore.yaml && exec trivy image --cache-dir /cache --skip-db-update --quiet --scanners vuln,secret --severity HIGH,CRITICAL --ignorefile /tmp/ignore.yaml --exit-code 1 $image" < .trivyignore.yaml
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v drydock-grype-db:/cache -e GRYPE_DB_CACHE_DIR=/cache -e GRYPE_DB_AUTO_UPDATE=false -v "$PWD/.grype.yaml:/grype.yaml:ro" "$GRYPE" -c /grype.yaml --fail-on high "docker:$image"
done
docker image rm drydock:scan drydock:scan-arm64
```

New CVEs are published daily, so a scan that passed for the previous release says nothing about this one. Fix or except every finding before the tag: a pushed tag is never moved, so a finding found after it means another patch release.

The scans fail on any high or critical finding that `.trivyignore.yaml` (Trivy) or `.grype.yaml` (Grype) does not list. The two scanners use different databases, so each finds things the other misses. A finding excepted for both gets an entry in each, with the same reason. Each entry names the CVE, why drydock is not exposed, and an expiry date (an `expired_at` field for Trivy, an `# expires` comment for Grype, which has no expiry field); review it then rather than moving the date.

The integration tests reach the host's Docker daemon through the same socket proxy as production and create (then remove) containers and volumes there. A privileged `docker:dind` container running sshd stands in for a remote host; the tests generate the SSH key pair in memory and authorize it at test time. The Phase 1 spikes (marked `slow`) move a gigabyte through each path and need about 4 GB free in the Docker VM; `pytest -m 'not slow'` skips them.

## Releases

A tag `vX.Y.Z` that matches `version` in `pyproject.toml` runs the release workflow on the self-hosted Forgejo runner. It builds amd64 and arm64, checks that each carries an SBOM and provenance and that the arm64 image starts, then pushes `X.Y.Z` and `X.Y` to the Forgejo instance's container registry (`<forgejo host>/<owner>/drydock`) from the same build. It runs no tests and no vulnerability scans, so tag only a commit whose local suite and audits passed.

The job logs in with the repository Actions secret `REGISTRY_TOKEN`, a Forgejo access token of the repository owner with the `write:package` scope and nothing else. Without it, tags fail at the publish step.

Before tagging a release that adds a migration, add its upgrade fixture (`tests/fixtures/upgrade/<revision>.sql`) so the next release's migrations are tested against a database it wrote:

```sh
docker compose -f compose.test.yaml run --rm --no-deps tests uv run --no-sync python -m tests.upgrade_fixture tests/fixtures/upgrade "$(git rev-parse --short HEAD)"
```

`tests/test_upgrade.py` fails while the head revision has no fixture. Add the release to `CHANGELOG.md`.

## Frontend rules

- The CSP allows no inline scripts, inline styles or eval. Scripts need the per-response nonce, and DOM HTML sinks are limited to htmx's Trusted Types policy.
- No `hx-on` attributes. Client behaviour lives in `frontend/app.ts`.
- Every element with an `hx-` attribute carries `hx-nonce="{{ csp_nonce }}"`. The hx-csp extension strips htmx attributes from any element without it, so injected markup cannot send requests that inherit the CSRF header.
- One stylesheet, `/static/css/app.css`, compiled from `frontend/app.css` by the Tailwind CLI. daisyUI components that embed `data:` URLs are excluded.
