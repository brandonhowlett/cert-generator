#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/cert-lib.sh"

require_cmd openssl

# =========================
# Defaults
# =========================

OUT_DIR="./certs"
ROOT_CA_KEY=""
CA_CN="Local Root CA"
CN="localhost"
SUBJECT_EXTRA=""
SANS=()
PROFILE="both"

INSTALL_TRUST=""
EMIT_K8S=0
K8S_NAME="local-tls"
K8S_NS="default"

EMIT_TRAEFIK=0
TRAEFIK_DIR=""

EMIT_SOPS=0
NON_INTERACTIVE=0

# =========================
# Flags
# =========================

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --root-ca-key) ROOT_CA_KEY="$2"; shift 2 ;;
    --ca-cn) CA_CN="$2"; shift 2 ;;
    --cn) CN="$2"; shift 2 ;;
    --subject-extra) SUBJECT_EXTRA="$2"; shift 2 ;;
    --san) SANS+=("$2"); shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --install-trust) INSTALL_TRUST="$2"; shift 2 ;;
    --emit-k8s-secret) EMIT_K8S=1; shift ;;
    --k8s-name) K8S_NAME="$2"; shift 2 ;;
    --k8s-namespace) K8S_NS="$2"; shift 2 ;;
    --emit-traefik) EMIT_TRAEFIK=1; TRAEFIK_DIR="$2"; shift 2 ;;
    --emit-sops) EMIT_SOPS=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help)
      sed -n '1,200p' "$SCRIPT_DIR/README.md"
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# =========================
# Interactive prompts
# =========================

if (( NON_INTERACTIVE == 0 )); then
  read -rp "Output directory [$OUT_DIR]: " v && OUT_DIR="${v:-$OUT_DIR}"
  [[ -z "$ROOT_CA_KEY" ]] && read -rp "Root CA key path (empty=auto): " ROOT_CA_KEY
  read -rp "CA Common Name [$CA_CN]: " v && CA_CN="${v:-$CA_CN}"
  read -rp "Leaf Common Name [$CN]: " v && CN="${v:-$CN}"

  if [[ "$PROFILE" == "both" ]]; then
    read -rp "Profile (server/client/both) [both]: " v
    PROFILE="${v:-both}"
  fi

  if [[ ${#SANS[@]} -eq 0 ]]; then
    read -rp "Add SANs? [Y/n]: " yn
    [[ "${yn,,}" != "n" ]] && {
      while true; do
        read -rp "SAN (DNS:x / IP:x, empty=done): " san
        [[ -z "$san" ]] && break
        SANS+=("$san")
      done
    }
  fi

  [[ -z "$SUBJECT_EXTRA" ]] && read -rp "Extra subject attrs (/O= /OU= /C= ...): " SUBJECT_EXTRA
  read -rp "Install trust? (linux/macos/firefox/skip) [skip]: " v
  [[ "$v" != "skip" ]] && INSTALL_TRUST="$v"

  read -rp "Emit Kubernetes TLS secret? [y/N]: " v
  [[ "${v,,}" == "y" ]] && EMIT_K8S=1

  read -rp "Emit Traefik bundle? [y/N]: " v
  [[ "${v,,}" == "y" ]] && {
    read -rp "Traefik output dir: " TRAEFIK_DIR
    EMIT_TRAEFIK=1
  }

  read -rp "Generate SOPS-encrypted files? [y/N]: " v
  [[ "${v,,}" == "y" ]] && EMIT_SOPS=1
fi

# =========================
# Paths
# =========================

ensure_dir "$OUT_DIR"

ROOT_CA_KEY="${ROOT_CA_KEY:-$OUT_DIR/root-ca.key}"
ROOT_CA_CRT="$OUT_DIR/local-ca.crt"
LEAF_KEY="$OUT_DIR/local-key.pem"
LEAF_CERT="$OUT_DIR/local-cert.pem"
CSR="$OUT_DIR/local.csr"
CONF="$(mktemp)"

# =========================
# CA
# =========================

[[ -f "$ROOT_CA_KEY" ]] || generate_root_key "$ROOT_CA_KEY"
[[ -f "$ROOT_CA_CRT" ]] || generate_ca_cert "$ROOT_CA_KEY" "$ROOT_CA_CRT" "/CN=$CA_CN"

# =========================
# Leaf
# =========================

SUBJECT="/CN=$CN${SUBJECT_EXTRA}"

generate_leaf_key "$LEAF_KEY"
generate_openssl_conf "$CONF" "$SUBJECT" "$PROFILE" "${SANS[@]}"
generate_csr "$LEAF_KEY" "$CSR" "$CONF"
sign_cert "$CSR" "$ROOT_CA_CRT" "$ROOT_CA_KEY" "$LEAF_CERT" "$CONF"

rm -f "$CONF"

# =========================
# Optional outputs
# =========================

(( EMIT_K8S == 1 )) && emit_k8s_secret \
  "$K8S_NAME" "$K8S_NS" "$OUT_DIR/${K8S_NAME}-secret.yaml" \
  "$LEAF_CERT" "$LEAF_KEY" "$ROOT_CA_CRT"

(( EMIT_TRAEFIK == 1 )) && emit_traefik_bundle \
  "$LEAF_CERT" "$ROOT_CA_CRT" "$LEAF_KEY" "$TRAEFIK_DIR"

if [[ -n "$INSTALL_TRUST" ]]; then
  case "$INSTALL_TRUST" in
    linux) install_trust_linux "$ROOT_CA_CRT" ;;
    macos) install_trust_macos "$ROOT_CA_CRT" ;;
    firefox) install_trust_firefox "$ROOT_CA_CRT" ;;
    *) echo "Unknown trust target: $INSTALL_TRUST"; exit 1 ;;
  esac
fi

# =========================
# SOPS
# =========================

if (( EMIT_SOPS == 1 )); then
  require_sops
  
  [[ -z "${SOPS_AGE_RECIPIENTS:-}" && ! -f "$HOME/.config/sops/age/keys.txt" ]] && {
    echo "ERROR: SOPS_AGE_RECIPIENTS not set and no AGE keys found at ~/.config/sops/age/keys.txt" >&2
    exit 1
  }
  
  sops_encrypt_file "$LEAF_KEY" "$LEAF_KEY.sops" || exit 1
  sops_encrypt_file "$LEAF_CERT" "$LEAF_CERT.sops" || exit 1
  sops_encrypt_file "$ROOT_CA_CRT" "$ROOT_CA_CRT.sops" || exit 1

  (( EMIT_K8S == 1 )) && \
    sops_encrypt_yaml \
      "$OUT_DIR/${K8S_NAME}-secret.yaml" \
      "$OUT_DIR/${K8S_NAME}-secret.yaml.sops.yaml" || exit 1
  
  echo "✔ SOPS encryption complete; encrypted files written as *.sops" >&2
fi

echo "✔ Certificates generated in $OUT_DIR"
