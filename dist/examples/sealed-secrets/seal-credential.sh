#!/bin/bash
# T5.5 — seal a credential into a systemd-creds-encrypted blob.
#
# Usage:
#   sudo bash seal-credential.sh <credential_name> <output_path>
#
# Examples:
#   sudo bash seal-credential.sh openai_token /etc/locksmith/credentials/openai.enc
#
# The credential plaintext is read from stdin (or interactively when stdin
# is a tty). The plaintext is never written to disk; systemd-creds
# encrypt streams stdin → encrypted output.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <credential_name> <output_path>" >&2
    echo "  credential_name must match the LoadCredentialEncrypted=<name>:..." >&2
    echo "  directive in your locksmith.service unit." >&2
    exit 2
fi

NAME=$1
OUT=$2

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (systemd-creds writes to root-owned paths)" >&2
    exit 1
fi

if ! command -v systemd-creds >/dev/null 2>&1; then
    echo "error: systemd-creds not found (need systemd >= 250)" >&2
    exit 1
fi

# Make sure the destination directory exists with restrictive perms.
DIR=$(dirname -- "$OUT")
install -d -m 0700 "$DIR"

# Read plaintext from stdin (or prompt). `read -s` hides the input.
if [[ -t 0 ]]; then
    read -rs -p "Credential plaintext: " PLAINTEXT
    echo
else
    PLAINTEXT=$(cat)
fi

# Pipe plaintext to systemd-creds; never touch disk in cleartext.
# --name binds the blob to this exact credential name; the matching
# LoadCredentialEncrypted= directive in the unit must use the same name.
printf '%s' "$PLAINTEXT" | \
    systemd-creds encrypt --name="$NAME" - "$OUT"

# Clear the variable from this shell's memory.
PLAINTEXT=""

# Lock down: root-readable only.
chmod 0600 "$OUT"

echo "Sealed credential written to: $OUT"
echo "Reference it from your unit as:"
echo "  LoadCredentialEncrypted=$NAME:$OUT"
