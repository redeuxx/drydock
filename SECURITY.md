# Security policy

## Reporting a vulnerability

Report vulnerabilities privately to the maintainer, `redeuxx` on [git.wenberg.net](https://git.wenberg.net/redeuxx), and not in a public issue. Include the drydock version (or commit), how you deploy it, and the steps to reproduce. You should get an answer within a week. A fix is released as a patch version and noted in [CHANGELOG.md](CHANGELOG.md), with credit if you want it.

## Supported versions

Only the latest `X.Y` release line gets security fixes. Upgrade to its newest patch release (the `X.Y` image tag follows it).

## What drydock protects, and what it does not

Drydock controls Docker on every host it manages, so it is root-equivalent on all of them by design. [docs/threat-model.md](docs/threat-model.md) lists the assets, attackers and trust boundaries, every threat with its defence and the tests that cover it, and the risks v1 accepts. These are not vulnerabilities in themselves:

- Anyone with a superadmin account, the secret key or code execution in the drydock container controls the managed hosts.
- The socket proxy narrows the local Docker API but is not a security boundary, and the remote SSH user is root-equivalent on its host.
- Admins can restore signed archives that carry no risk flags.
- Unencrypted archives expose environment variables and `.env` files to whoever can read the storage.
- Plain-HTTP LAN deployments send the session cookie without `Secure`, and there is no second factor yet.

A way around any defence the threat model claims (for example, a viewer changing state, a restore writing to a denied host path, an unsigned archive restored without a superadmin, or a secret appearing in a page or log) is a vulnerability. So is anything that lets someone without an account act on drydock after setup.

## Deploying safely

The README's [Read this first](README.md#read-this-first) section covers the setup wizard risk, the loopback binding and SSH tunnel, the secret key file's ownership and backup, and reverse proxy settings. In short: complete `/setup` right after the first start over an SSH tunnel, keep port 8000 on 127.0.0.1, keep the secret key apart from `/data`, and keep jobs encrypted.

## Supply chain

- Every base image, build tool and CI image is pinned by digest, and the age and rclone binaries by SHA-256.
- CI runs `pip-audit` and `npm audit` on the dependencies, and Trivy (vulnerabilities and secrets) on the amd64 and arm64 images. High and critical findings fail the build unless `.trivyignore.yaml` lists them with a reason and an expiry date.
- Release images carry an SPDX SBOM and SLSA provenance, built and published from the same CI run that scanned them.
