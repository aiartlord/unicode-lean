#!/usr/bin/env bash
# Build release evidence artifacts:
#   - source archive from a git commit
#   - CycloneDX JSON SBOM for the source/data/toolchain boundary
#   - SHA-256 manifest covering the emitted artifacts

set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-${GITHUB_REF_NAME:-$(git describe --tags --always)}}"
out_dir="${2:-dist}"
commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"

case "$version" in
  *[!A-Za-z0-9._-]*|'')
    echo "FATAL: release version must contain only A-Z, a-z, 0-9, '.', '_', '-'"
    exit 1
    ;;
esac

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

mkdir -p "$out_dir"

archive="$out_dir/unicode-lean-${version}.source.tar.gz"
sbom="$out_dir/unicode-lean-${version}.sbom.cdx.json"
manifest="$out_dir/SHA256SUMS"

git archive --format=tar --prefix="unicode-lean-${version}/" "$commit" \
  | gzip -n > "$archive"

repo_url="$(git config --get remote.origin.url || true)"
toolchain="$(tr -d '\n' < lean-toolchain)"
commit_date="$(git show -s --format=%cI "$commit")"

ucd_manifest_hash="$(sha256_file Unicode/Ucd/SHA256SUMS)"
security_manifest_hash="$(sha256_file Unicode/Ucd/Security/SHA256SUMS)"
bip39_manifest_hash="$(sha256_file Unicode/Ucd/BIP39/SHA256SUMS)"
curated_manifest_hash="$(sha256_file Unicode/Ucd/Curated/SHA256SUMS)"
flake_lock_hash="$(sha256_file flake.lock)"
lake_manifest_hash="$(sha256_file lake-manifest.json)"

cat > "$sbom" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "$(json_escape "$commit_date")",
    "component": {
      "type": "application",
      "name": "unicode-lean",
      "version": "$(json_escape "$version")",
      "bom-ref": "unicode-lean",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "$(json_escape "$repo_url")"
        }
      ],
      "properties": [
        {
          "name": "git.commit",
          "value": "$(json_escape "$commit")"
        }
      ]
    }
  },
  "components": [
    {
      "type": "framework",
      "name": "Lean",
      "version": "$(json_escape "$toolchain")",
      "bom-ref": "lean-toolchain"
    },
    {
      "type": "data",
      "name": "Unicode UCD/UCA source data",
      "version": "17.0.0",
      "bom-ref": "unicode-ucd",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "$(json_escape "$ucd_manifest_hash")"
        }
      ],
      "properties": [
        {
          "name": "manifest",
          "value": "Unicode/Ucd/SHA256SUMS"
        }
      ]
    },
    {
      "type": "data",
      "name": "Security conformance fixtures",
      "bom-ref": "unicode-security-fixtures",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "$(json_escape "$security_manifest_hash")"
        }
      ],
      "properties": [
        {
          "name": "manifest",
          "value": "Unicode/Ucd/Security/SHA256SUMS"
        }
      ]
    },
    {
      "type": "data",
      "name": "BIP-39 wordlists",
      "bom-ref": "bip39-wordlists",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "$(json_escape "$bip39_manifest_hash")"
        }
      ],
      "properties": [
        {
          "name": "manifest",
          "value": "Unicode/Ucd/BIP39/SHA256SUMS"
        }
      ]
    },
    {
      "type": "data",
      "name": "Project-curated security baselines",
      "bom-ref": "curated-security-baselines",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "$(json_escape "$curated_manifest_hash")"
        }
      ],
      "properties": [
        {
          "name": "manifest",
          "value": "Unicode/Ucd/Curated/SHA256SUMS"
        }
      ]
    },
    {
      "type": "file",
      "name": "flake.lock",
      "bom-ref": "flake-lock",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "$(json_escape "$flake_lock_hash")"
        }
      ]
    },
    {
      "type": "file",
      "name": "lake-manifest.json",
      "bom-ref": "lake-manifest",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "$(json_escape "$lake_manifest_hash")"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "unicode-lean",
      "dependsOn": [
        "lean-toolchain",
        "unicode-ucd",
        "unicode-security-fixtures",
        "bip39-wordlists",
        "curated-security-baselines",
        "flake-lock",
        "lake-manifest"
      ]
    }
  ]
}
EOF

(
  cd "$out_dir"
  sha256sum "$(basename "$archive")" "$(basename "$sbom")" > "$(basename "$manifest")"
)

echo "wrote $archive"
echo "wrote $sbom"
echo "wrote $manifest"
