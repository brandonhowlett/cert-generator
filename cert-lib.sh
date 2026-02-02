#!/usr/bin/env bash
set -euo pipefail

# =========================
# Common helpers
# =========================

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

ensure_dir() {
  mkdir -p "$1"
}

# =========================
# Root CA
# =========================

generate_root_key() {
  local key="$1"
  openssl genrsa -out "$key" 4096
}

generate_ca_cert() {
  local key="$1" crt="$2" subj="$3" days="${4:-3650}"
  openssl req -x509 -new -key "$key" \
    -sha256 -days "$days" \
    -out "$crt" \
    -subj "$subj"
}

# =========================
# Leaf cert generation
# =========================

generate_leaf_key() {
  local key="$1"
  openssl genrsa -out "$key" 2048
}

generate_openssl_conf() {
  local file="$1" subject="$2" profile="$3"; shift 3
  local sans=("$@")

  local eku
  case "$profile" in
    server) eku="serverAuth" ;;
    client) eku="clientAuth" ;;
    both) eku="serverAuth,clientAuth" ;;
    *)
      echo "ERROR: invalid profile: $profile" >&2
      exit 1
      ;;
  esac

  {
    echo "[ req ]"
    echo "distinguished_name = dn"
    echo "req_extensions = v3_req"
    echo "prompt = no"
    echo
    echo "[ dn ]"
    sed 's|/|\n|g' <<<"$subject" | sed '/^$/d'
    echo
    echo "[ v3_req ]"
    echo "basicConstraints = CA:FALSE"
    echo "keyUsage = digitalSignature, keyEncipherment"
    echo "extendedKeyUsage = $eku"

    if [[ "$profile" == "server" || "$profile" == "both" ]]; then
      if (( ${#sans[@]} == 0 )); then
        echo "ERROR: server certificates require SANs" >&2
        exit 1
      fi
    fi

    if (( ${#sans[@]} > 0 )); then
      echo "subjectAltName = @alt_names"
      echo
      echo "[ alt_names ]"
      local i=1
      for san in "${sans[@]}"; do
        echo "${san%%:*}.$i = ${san#*:}"
        ((i++))
      done
    fi
  } > "$file"
}

generate_csr() {
  local key="$1" csr="$2" conf="$3"
  openssl req -new -key "$key" -out "$csr" -config "$conf"
}

sign_cert() {
  local csr="$1" ca_crt="$2" ca_key="$3" out="$4" conf="$5"
  openssl x509 -req \
    -in "$csr" \
    -CA "$ca_crt" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$out" \
    -days 825 \
    -sha256 \
    -extfile "$conf" \
    -extensions v3_req
}

# =========================
# Trust store installation
# =========================

install_trust_linux() {
  local ca_crt="$1"
  [[ -f "$ca_crt" ]] || { echo "ERROR: certificate not found: $ca_crt" >&2; return 1; }
  local dst="/usr/local/share/ca-certificates/$(basename "$ca_crt")"
  echo "Installing $ca_crt to system trust store at $dst..."
  sudo cp "$ca_crt" "$dst" || { echo "ERROR: failed to copy cert" >&2; return 1; }
  sudo update-ca-certificates || { echo "WARNING: update-ca-certificates failed" >&2; }
}

install_trust_macos() {
  local ca_crt="$1"
  sudo security add-trusted-cert \
    -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "$ca_crt"
}

install_trust_firefox() {
  local ca_crt="$1"
  local profile_dir
  profile_dir=$(find "$HOME/.mozilla/firefox" -maxdepth 1 -type d -name "*.default*" | head -n1)

  [[ -z "$profile_dir" ]] && {
    echo "ERROR: Firefox profile not found" >&2
    exit 1
  }

  certutil -A \
    -n "Local Root CA" \
    -t "C,," \
    -i "$ca_crt" \
    -d "sql:$profile_dir"
}

# =========================
# Output helpers
# =========================

emit_k8s_secret() {
  local name="$1" namespace="$2" out="$3"
  local crt="$4" key="$5" ca="$6"

  cat > "$out" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: $name
  namespace: $namespace
type: kubernetes.io/tls
data:
  tls.crt: $(base64 -w0 < "$crt")
  tls.key: $(base64 -w0 < "$key")
  ca.crt:  $(base64 -w0 < "$ca")
EOF
}

emit_traefik_bundle() {
  local crt="$1" ca="$2" key="$3" outdir="$4"
  mkdir -p "$outdir"
  cat "$crt" "$ca" > "$outdir/fullchain.pem"
  cp "$key" "$outdir/key.pem"
}

# =========================
# SOPS helpers
# =========================

require_sops() {
  command -v sops >/dev/null 2>&1 || {
    echo "ERROR: sops not found but encryption requested" >&2
    exit 1
  }
}

sops_encrypt_file() {
  local in="$1" out="$2"
  [[ -f "$in" ]] || { echo "ERROR: file not found: $in" >&2; return 1; }
  sops --encrypt "$in" > "$out" || {
    echo "ERROR: failed to encrypt $in" >&2
    return 1
  }
}

sops_encrypt_yaml() {
  local in="$1" out="$2"
  [[ -f "$in" ]] || { echo "ERROR: file not found: $in" >&2; return 1; }
  sops --encrypt --input-type yaml --output-type yaml "$in" > "$out" || {
    echo "ERROR: failed to encrypt YAML $in" >&2
    return 1
  }
}
