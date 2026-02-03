#!/usr/bin/env bash
set -euo pipefail

# Get script directory (works in both bash and zsh)
SCRIPT_DIR="${0%/*}"
[[ "$SCRIPT_DIR" == "$0" ]] && SCRIPT_DIR="."
source "$SCRIPT_DIR/cert-lib.sh"

require_cmd openssl

# =========================
# Help function
# =========================

show_help() {
  cat <<'EOF'
cert-generator — Local PKI & Certificate Generation Tool

SYNOPSIS
  cert-tool.sh [OPTIONS]

DESCRIPTION
  Interactive or non-interactive certificate generation with optional Kubernetes,
  Traefik, and SOPS encryption outputs.

OPTIONS
  Output & Paths
    --out-dir DIR                      Output directory for artifacts (default: ./certs)
    -d, --dir DIR                      Alias for --out-dir
    --root-ca-key FILE                 Existing root CA private key (auto-generated if missing)
    --root-ca-cert FILE                Existing root CA certificate (skips CA cert generation)

  Certificate Subject
    --cn COMMON_NAME                   Leaf certificate Common Name (default: localhost)
    --ca-cn NAME                       Root CA Common Name (default: "Local Root CA")
    --subject-extra ATTRS              Extra subject attributes (e.g., "/O=Org/C=US/ST=State")
    --san SAN                          Subject Alternative Name (repeatable; e.g., DNS:example.local, IP:192.168.1.1)

  Certificate Options
    --profile {server|client|both}     Certificate profile/EKU (default: both)

  Optional Outputs
    --emit-k8s-secret                  Generate Kubernetes TLS Secret YAML
    --k8s-name NAME                    Secret name (default: local-tls)
    --k8s-namespace NS                 Secret namespace (default: default)
    --emit-traefik DIR                 Generate Traefik PEM bundle (fullchain.pem + key.pem)
    --emit-traefik-k8s-secret          Generate Traefik Kubernetes Secret YAML
    --traefik-k8s-name NAME            Traefik secret name (default: local-certs)
    --traefik-k8s-namespace NS         Traefik secret namespace (default: traefik)
    --emit-sops                        Generate SOPS-encrypted siblings (requires sops + AGE keys)
    --sops-config FILE                 Path to .sops.yaml config (uses fallback if not found)

  Trust Store
    --install-trust {linux|macos|firefox}
                                       Install root CA to system trust store

  Mode
    --non-interactive                  Skip interactive prompts; use defaults/provided flags
    -i                                 Alias for --non-interactive

  Help
    -h, --help                         Show this help message and exit

EXAMPLES
  # Interactive mode
  ./cert-tool.sh

  # Non-interactive: create cert with SANs
  ./cert-tool.sh --cn "example.local" --san "DNS:example.local" --san "IP:192.168.1.10" --non-interactive

  # Emit Kubernetes secret and SOPS encryption
  ./cert-tool.sh --emit-k8s-secret --emit-sops --non-interactive

  # Traefik bundle with custom output dir
  ./cert-tool.sh --emit-traefik ./traefik --out-dir ./artifacts --non-interactive

ENVIRONMENT
  SOPS_AGE_RECIPIENTS                 AGE recipients for sops encryption (colon-separated)
  HOME/.config/sops/age/keys.txt      Default location for AGE private keys

SAFETY
  • Never overwrites existing private keys without confirmation
  • Plaintext artifacts always generated first; encryption is additive
  • Fails fast on invalid input or missing dependencies

SEE ALSO
  README.md for detailed documentation
  cert-lib.sh for helper functions
EOF
}

# =========================
# Defaults
# =========================

OUT_DIR="./certs"
ROOT_CA_KEY=""
ROOT_CA_CERT=""
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

EMIT_TRAEFIK_K8S=0
TRAEFIK_K8S_NAME="local-certs"
TRAEFIK_K8S_NS="traefik"

EMIT_SOPS=0
SOPS_CONFIG=""
NON_INTERACTIVE=0

# =========================
# Flags
# =========================

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir|-d) OUT_DIR="$2"; shift 2 ;;
    --root-ca-key) ROOT_CA_KEY="$2"; shift 2 ;;
    --root-ca-cert) ROOT_CA_CERT="$2"; shift 2 ;;
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
    --emit-traefik-k8s-secret) EMIT_TRAEFIK_K8S=1; shift ;;
    --traefik-k8s-name) TRAEFIK_K8S_NAME="$2"; shift 2 ;;
    --traefik-k8s-namespace) TRAEFIK_K8S_NS="$2"; shift 2 ;;
    --emit-sops) EMIT_SOPS=1; shift ;;
    --sops-config) SOPS_CONFIG="$2"; shift 2 ;;
    --non-interactive|-i) NON_INTERACTIVE=1; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1"; echo "Use -h or --help for usage information"; exit 1 ;;
  esac
done

# =========================
# Interactive prompts
# =========================

# Helper: read path with readline support & suggestions
read_path_input() {
  local prompt="${1:-}" default="${2:-}" input="${2:-}"
  
  # Guard against missing parameters
  [[ -z "$prompt" ]] && prompt="Input"
  
  # Use read -e for interactive mode only (with TTY check)
  if [[ -t 0 ]]; then
    # Interactive: use readline for editing, history, completion
    read -e -p "$prompt [$default]: " input || input="$default"
  else
    # Non-interactive: prompt to stderr, read from stdin
    echo -n "$prompt [$default]: " >&2
    read input || input="$default"
  fi
  input="${input:-$default}"
  
  echo "$input"
}

# Helper: read generic input with suggestion
read_input() {
  local prompt="${1:-}" default="${2:-}" input="${2:-}"
  
  # Guard against missing parameters
  [[ -z "$prompt" ]] && prompt="Input"
  
  # Use read -e for interactive mode only
  if [[ -t 0 ]]; then
    read -e -p "$prompt [$default]: " input || input="$default"
  else
    # Non-interactive: prompt to stderr, read from stdin
    echo -n "$prompt [$default]: " >&2
    read input || input="$default"
  fi
  echo "${input:-$default}"
}

if (( NON_INTERACTIVE == 0 )); then
  OUT_DIR="$(read_path_input "Output directory" "$OUT_DIR")"
  [[ -z "$ROOT_CA_KEY" ]] && ROOT_CA_KEY="$(read_input "Root CA key path (empty=auto)" "")"
  CA_CN="$(read_input "CA Common Name" "$CA_CN")"
  CN="$(read_input "Leaf Common Name" "$CN")"

  if [[ "$PROFILE" == "both" ]]; then
    if [[ -t 0 ]]; then
      read -rp "Profile (server/client/both) [both]: " v
    else
      echo -n "Profile (server/client/both) [both]: " >&2
      read v || v=""
    fi
    PROFILE="${v:-both}"
  fi

  if [[ ${#SANS[@]} -eq 0 ]]; then
    if [[ -t 0 ]]; then
      read -rp "Add SANs? [Y/n]: " yn
    else
      echo -n "Add SANs? [Y/n]: " >&2
      read yn || yn=""
    fi
    [[ "$(echo "$yn" | tr '[:upper:]' '[:lower:]')" != "n" ]] && {
      while true; do
        if [[ -t 0 ]]; then
          read -rp "SAN (DNS:x / IP:x, empty=done): " san
        else
          echo -n "SAN (DNS:x / IP:x, empty=done): " >&2
          read san || san=""
        fi
        [[ -z "$san" ]] && break
        SANS+=("$san")
      done
    }
  fi

  [[ -z "$SUBJECT_EXTRA" ]] && SUBJECT_EXTRA="$(read_input "Extra subject attrs (/O= /OU= /C= ...)" "")"
  if [[ -t 0 ]]; then
    read -rp "Install trust? (linux/macos/firefox/skip) [skip]: " v
  else
    echo -n "Install trust? (linux/macos/firefox/skip) [skip]: " >&2
    read v || v=""
  fi
  [[ "$v" != "skip" ]] && INSTALL_TRUST="$v"

  if [[ -t 0 ]]; then
    read -rp "Emit Kubernetes TLS secret? [y/N]: " v
  else
    echo -n "Emit Kubernetes TLS secret? [y/N]: " >&2
    read v || v=""
  fi
  [[ "$(echo "$v" | tr '[:upper:]' '[:lower:]')" == "y" ]] && EMIT_K8S=1

  if [[ -t 0 ]]; then
    read -rp "Emit Traefik bundle? [y/N]: " v
  else
    echo -n "Emit Traefik bundle? [y/N]: " >&2
    read v || v=""
  fi
  [[ "$(echo "$v" | tr '[:upper:]' '[:lower:]')" == "y" ]] && {
    TRAEFIK_DIR="$(read_path_input "Traefik output dir" "./traefik")"
    EMIT_TRAEFIK=1
  }

  if [[ -t 0 ]]; then
    read -rp "Generate SOPS-encrypted files? [y/N]: " v
  else
    echo -n "Generate SOPS-encrypted files? [y/N]: " >&2
    read v || v=""
  fi
  [[ "$(echo "$v" | tr '[:upper:]' '[:lower:]')" == "y" ]] && EMIT_SOPS=1
fi

# =========================
# Paths
# =========================

ensure_dir "$OUT_DIR"

ROOT_CA_KEY="${ROOT_CA_KEY:-$OUT_DIR/root-ca.key}"
ROOT_CA_CRT="${ROOT_CA_CERT:-$OUT_DIR/local-ca.crt}"
LEAF_KEY="$OUT_DIR/local-key.pem"
LEAF_CERT="$OUT_DIR/local-cert.pem"
CSR="$OUT_DIR/local.csr"
CONF="$(mktemp)"

# =========================
# CA
# =========================

[[ -f "$ROOT_CA_KEY" ]] || generate_root_key "$ROOT_CA_KEY"
[[ -n "$ROOT_CA_CERT" && -f "$ROOT_CA_CERT" ]] || generate_ca_cert "$ROOT_CA_KEY" "$ROOT_CA_CRT" "/CN=$CA_CN"

# =========================
# Leaf
# =========================

SUBJECT="/CN=$CN${SUBJECT_EXTRA}"

# Only generate leaf cert files if not emitting K8s secret or Traefik K8s secret
# (K8s secrets embed the cert, no need for intermediate files)
if (( EMIT_K8S == 0 && EMIT_TRAEFIK_K8S == 0 )); then
  generate_leaf_key "$LEAF_KEY"
  generate_openssl_conf "$CONF" "$SUBJECT" "$PROFILE" "${SANS[@]}"
  generate_csr "$LEAF_KEY" "$CSR" "$CONF"
  sign_cert "$CSR" "$ROOT_CA_CRT" "$ROOT_CA_KEY" "$LEAF_CERT" "$CONF"

  rm -f "$CONF"
else
  # For K8s secret or Traefik K8s secret, generate in temp files (will be embedded in secret)
  LEAF_KEY="$(mktemp)"
  LEAF_CERT="$(mktemp)"
  CSR="$(mktemp)"
  CONF="$(mktemp)"
  
  generate_leaf_key "$LEAF_KEY"
  generate_openssl_conf "$CONF" "$SUBJECT" "$PROFILE" "${SANS[@]}"
  generate_csr "$LEAF_KEY" "$CSR" "$CONF"
  sign_cert "$CSR" "$ROOT_CA_CRT" "$ROOT_CA_KEY" "$LEAF_CERT" "$CONF"
  
  trap "rm -f $LEAF_KEY $LEAF_CERT $CSR $CONF" EXIT
fi

# =========================
# Optional outputs
# =========================

(( EMIT_K8S == 1 )) && emit_k8s_secret \
  "$K8S_NAME" "$K8S_NS" "$OUT_DIR/${K8S_NAME}-secret.yaml" \
  "$LEAF_CERT" "$LEAF_KEY" "$ROOT_CA_CRT"

(( EMIT_TRAEFIK == 1 )) && emit_traefik_bundle \
  "$LEAF_CERT" "$ROOT_CA_CRT" "$LEAF_KEY" "$TRAEFIK_DIR"

(( EMIT_TRAEFIK_K8S == 1 )) && emit_traefik_k8s_secret \
  "$TRAEFIK_K8S_NAME" "$TRAEFIK_K8S_NS" "$OUT_DIR/${TRAEFIK_K8S_NAME}-secret.yaml" \
  "$LEAF_CERT" "$LEAF_KEY" "$ROOT_CA_CRT"

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
  
  # Determine .sops.yaml config file path
  sops_config_path=""
  if [[ -n "$SOPS_CONFIG" && -f "$SOPS_CONFIG" ]]; then
    sops_config_path="$SOPS_CONFIG"
  elif [[ -f "$OUT_DIR/.sops.yaml" ]]; then
    sops_config_path="$OUT_DIR/.sops.yaml"
  fi
  
  # Only encrypt individual files if not using K8s secret or Traefik K8s secret
  if (( EMIT_K8S == 0 && EMIT_TRAEFIK_K8S == 0 )); then
    sops_encrypt_file "$LEAF_KEY" "$OUT_DIR/local.sops.pem" "$sops_config_path" || exit 1
    sops_encrypt_file "$LEAF_CERT" "$OUT_DIR/local-cert.sops.pem" "$sops_config_path" || exit 1
    sops_encrypt_file "$ROOT_CA_CRT" "$OUT_DIR/local-ca.sops.crt" "$sops_config_path" || exit 1
  fi

  # Encrypt K8s secret if emitted
  if (( EMIT_K8S == 1 )); then
    sops_encrypt_yaml \
      "$OUT_DIR/${K8S_NAME}-secret.yaml" \
      "$OUT_DIR/${K8S_NAME}.sops.yaml" "$sops_config_path" || exit 1
  fi

  # Encrypt Traefik K8s secret if emitted
  if (( EMIT_TRAEFIK_K8S == 1 )); then
    sops_encrypt_yaml \
      "$OUT_DIR/${TRAEFIK_K8S_NAME}-secret.yaml" \
      "$OUT_DIR/${TRAEFIK_K8S_NAME}.sops.yaml" "$sops_config_path" || exit 1
  fi
  
  echo "✔ SOPS encryption complete; encrypted files written as *.sops.*" >&2
fi

echo "✔ Certificates generated in $OUT_DIR"
