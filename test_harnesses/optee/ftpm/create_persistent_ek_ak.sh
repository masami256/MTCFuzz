#!/bin/sh
# Busybox/sh compatible: create EK and AK and persist them.
# Usage:
#   ./create_persistent_ek_ak.sh [EK_HANDLE] [AK_HANDLE] [OWNER_AUTH] [ENDORSEMENT_AUTH]
# Example (no auth):
#   ./create_persistent_ek_ak.sh 0x81010001 0x81010002

set -eu

EK_HANDLE=${1:-0x81010001}
AK_HANDLE=${2:-0x81010002}
OWNER_AUTH=${3:-}
ENDORSEMENT_AUTH=${4:-}

# helper: add -P only if non-empty
auth_opt() {
  [ -n "$1" ] && printf "%s" "-P $1" || printf "%s" ""
}

echo "Creating EK and persisting to $EK_HANDLE ..."
# create EK (rsa)
# if Endorsement auth is set, pass it to createek with -P <auth> (some tpm2-tools versions accept -P)
# many tpm2-tools have tpm2_createek -G rsa -u ek.pub -c ek.ctx
if command -v tpm2_createek >/dev/null 2>&1; then
  tpm2_createek -G rsa -u ek.pub -c ek.ctx
else
  echo "ERROR: tpm2_createek not found" >&2
  exit 1
fi

echo "Persisting EK to $EK_HANDLE (owner control) ..."
if [ -n "$OWNER_AUTH" ]; then
  tpm2_evictcontrol -C o -c ek.ctx "$EK_HANDLE" -P "$OWNER_AUTH"
else
  tpm2_evictcontrol -C o -c ek.ctx "$EK_HANDLE"
fi

echo "Creating AK under EK handle $EK_HANDLE ..."
# createak can accept -C <handle> numeric
# some tpm2-tools accept -C e (endorsement) but numeric parent handle is robust
tpm2_createak -C "$EK_HANDLE" -u ak.pub -n ak.name -c ak.ctx \
  --key-alg rsa --hash-alg sha256 --signing-alg rsassa

echo "Persisting AK to $AK_HANDLE ..."
if [ -n "$OWNER_AUTH" ]; then
  tpm2_evictcontrol -C o -c ak.ctx "$AK_HANDLE" -P "$OWNER_AUTH"
else
  tpm2_evictcontrol -C o -c ak.ctx "$AK_HANDLE"
fi

echo "Exporting AK as PEM (ak.pem) for external verification (if supported)..."
# Some tpm2-tools versions allow direct PEM export of a persistent handle by reading it into ctx first.
tpm2_readpublic -c ak.ctx -f pem -o ak.pem || echo "Warning: tpm2_readpublic -f pem unsupported on this tpm2-tools version."

echo ""
echo "Done."
echo "EK handle: $EK_HANDLE"
echo "AK handle: $AK_HANDLE"
echo "Files created: ek.ctx ek.pub ak.ctx ak.pub ak.name ak.pem (if created)"
echo "You may remove persistent handles with: tpm2_evictcontrol -C o $EK_HANDLE ; tpm2_evictcontrol -C o $AK_HANDLE"
