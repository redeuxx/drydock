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

CI runs only on a self-hosted Forgejo instance (Forgejo Actions, `.forgejo/workflows/ci.yml`), on a runner whose jobs drive its host's Docker daemon; `compose.ci.yaml` swaps the checkout's bind mount for a volume there and skips the `slow` tests, whose latency ceilings a busy shared runner cannot hold. A newer push cancels the run in progress, and Markdown-only changes start none. The repository is pushed to GitHub too, without any workflow.

The integration tests reach the host's Docker daemon through the same socket proxy as production and create (then remove) containers and volumes there. A privileged `docker:dind` container running sshd stands in for a remote host; the tests generate the SSH key pair in memory and authorize it at test time. The Phase 1 spikes (marked `slow`) move a gigabyte through each path and need about 4 GB free in the Docker VM; `pytest -m 'not slow'` skips them.

## Releases

The `multiarch` CI job builds amd64 and arm64 on every push, scans both with Trivy and checks that each carries an SBOM and provenance. A tag `vX.Y.Z` that matches `version` in `pyproject.toml` then pushes `X.Y.Z` and `X.Y` to the Forgejo instance's container registry (`<forgejo host>/<owner>/drydock`), from the same build that was scanned. Push the branch first and the tag after: a newer push cancels a run in progress.

The job logs in with the repository Actions secret `REGISTRY_TOKEN`, a Forgejo access token of the repository owner with the `write:package` scope and nothing else. Without it, tags fail at the publish step.

The scan fails on any high or critical finding that `.trivyignore.yaml` does not list. Each entry there names the CVE, why drydock is not exposed, the files it applies to when it is in one binary, and an expiry date, after which the scan fails on it again; review it then rather than moving the date.

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
