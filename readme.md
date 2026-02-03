## cert-generator

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![sops compatible](https://img.shields.io/badge/sops-compatible-brightgreen.svg)](#) ![minimal](https://img.shields.io/badge/quality-minimal-lightgrey.svg)

Lightweight, reproducible local PKI tooling for Linux: generate a root CA, sign leaf certificates, and optionally emit Kubernetes secrets, Traefik bundles, and SOPS-encrypted artifacts for GitOps workflows.

### Table of contents
- [TL;DR](#tldr)
- [Features](#features)
- [Quickstart](#quickstart)
- [Examples](#examples)
- [Outputs & Files](#outputs--files)
- [SOPS & Flux](#sops--flux)
- [Safety Guarantees](#safety-guarantees)
- [Contributing](#contributing)
- [License](#license)

## TL;DR

Run the interactive generator to create a local root CA and one or more leaf certificates.

```bash
./cert-tool.sh --help   # Interactive CLI: create CA, keys, certs, optional outputs
./cert-lib.sh           # Shared helpers used by the toolset
```

## Features

- Deterministic, auditable PKI generation using OpenSSL
- Interactive prompts with sensible defaults (CN, SANs, key types)
- Root CA creation or reuse without overwriting existing keys
- Leaf certificate generation: RSA (2048/4096) and ECDSA (P-256/P-384)
- Optional outputs: Kubernetes `tls` Secret YAML, Traefik PEM bundles
- Optional SOPS-encrypted siblings compatible with Flux
- Safe-by-default: no in-place encryption, deletions, or silent overwrites

## Quickstart

1. Make the scripts executable (if needed):

```bash
chmod +x cert-tool.sh cert-lib.sh
```

2. Run the interactive generator and follow prompts:

```bash
./cert-tool.sh
```

The tool will detect an existing root CA (if present) and ask whether to reuse it or create a new one. Plaintext artifacts are written first; encrypted siblings are generated when SOPS mode is enabled.

## Examples

- Create a new root CA and a leaf cert (interactive prompts):

```bash
./cert-tool.sh
```

- Create with non-interactive flags:

```bash
./cert-tool.sh \
  --out-dir ./certs \
  --cn "example.local" \
  --san "DNS:example.local" \
  --san "IP:192.168.1.10"
```

- Emit a Kubernetes TLS Secret:

```bash
./cert-tool.sh \
  --emit-k8s-secret \
  --k8s-name example-tls \
  --k8s-namespace default
```

- Produce Traefik bundle and encrypt with SOPS:

```bash
./cert-tool.sh \
  --emit-traefik ./traefik \
  --emit-sops
```

## Outputs & Files

By default the generator emits plaintext artifacts. Common file names:

- `local-ca.key` — Root CA private key
- `local-ca.crt` — Root CA certificate
- `local-key.pem` — Leaf private key
- `local-cert.pem` — Leaf certificate
- `local-chain.pem` — Leaf + CA chain

When SOPS encryption is enabled, encrypted siblings are written alongside plaintext files using `.sops.` prefix before the extension (for example `local-cert.sops.pem`). YAML secrets are written as `secret.yaml` and encrypted as `secret.sops.yaml`.

## SOPS & Flux

Requirements:

- `sops` installed and in `PATH`
- Either `SOPS_AGE_RECIPIENTS` set in the environment or AGE keys available at `~/.config/sops/age/keys.txt`
- (Optional) `.sops.yaml` in repository root for default encryption settings

Behavior:

- Plaintext artifacts are generated first. Encryption is additive — originals are never modified or removed.
- Encrypted YAML artifacts produced by this tooling are compatible with Flux decryption (no additional transforms required).

Sample `.sops.yaml` (optional):

```yaml
encryption_method: age
keys:
  age:
  - &age_key AGEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
groups:
  - path_regex: ^.*\.sops\.(pem|crt|yaml|yml)$
    key_groups:
      - age:
          - *age_key
```

## Safety Guarantees

- Never overwrites existing private keys without explicit consent
- Avoids in-place encryption and implicit deletions
- Fails fast and emits clear error messages on invalid inputs

## Troubleshooting

- Verify certificates with OpenSSL:

```bash
openssl x509 -in local-cert.pem -noout -text
```

- Decrypt and preview an encrypted secret:

```bash
sops -d secret.yaml.sops.yaml | kubectl apply --dry-run=client -f -
```

## Contributing

Contributions welcome. Keep changes small and reviewable. Please open issues for feature requests and bugs.

## License

This repository is published under the MIT License. See the `LICENSE` file for details.

---

Edited to improve clarity and structure. For full implementation details see the scripts in this directory.

## CI & Flux examples

This repository includes two small examples to help automate certificate generation and consumption:

- GitHub Actions: `.github/workflows/cert-ci.yml` — a sample CI job that generates certificates, encrypts artifacts with `sops` (using AGE recipients supplied via repo secrets), and commits encrypted results back to the repo. Review and adapt the workflow before enabling in your environment.
- Flux Kustomization: `kustomization-flux-example.yaml` — an example `Kustomization` that points Flux at an encrypted `./certs` path and enables `sops` decryption on apply. Includes notes on cluster-side setup (AGE keys, sops-controller).

Place generated encrypted artifacts under the referenced `path` (for example `./certs`) so Flux can decrypt and apply them. Ensure cluster-side decryption (appropriate controllers/keys) is configured before using these examples.
