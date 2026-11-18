#!/usr/bin/env bash
# CI only: run enroll-tpm.sh against a software TPM (swtpm) instead of a real one. The swtpm gets
# an EK certificate from the CA in $DBA_SAMPLE_TPM_CA (ca.key, ca.crt), which the local test
# server trusts through TPM_EK_TEST_CA (scripts/run-samples.mjs); devicebasedauth.org itself
# trusts only TPM manufacturers' EK CAs, so a swtpm cannot attest there.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ca="${DBA_SAMPLE_TPM_CA:?set DBA_SAMPLE_TPM_CA to a directory with ca.key and ca.crt}"
work="$(mktemp -d)"
mkdir -p "$work/state" "$work/localca"
cat > "$work/localca.conf" <<CONF
statedir = $work/localca
signingkey = $ca/ca.key
issuercert = $ca/ca.crt
certserial = $work/localca/certserial
CONF
printf -- '--platform-manufacturer DBA\n--platform-version 2.1\n--platform-model sample\n' > "$work/localca.options"
cat > "$work/swtpm_setup.conf" <<CONF
create_certs_tool = $(command -v swtpm_localca)
create_certs_tool_config = $work/localca.conf
create_certs_tool_options = $work/localca.options
CONF
swtpm_setup --tpm2 --tpmstate "$work/state" --create-ek-cert --lock-nvram --config "$work/swtpm_setup.conf" --overwrite >/dev/null
port="$(( 23000 + RANDOM % 2000 ))"
swtpm socket --tpm2 --tpmstate dir="$work/state" --server type=tcp,port="$port" --ctrl type=tcp,port=$(( port + 1 )) --flags not-need-init,startup-clear &
swtpm_pid=$!
trap 'kill "$swtpm_pid" 2>/dev/null; wait "$swtpm_pid" 2>/dev/null; rm -rf "$work"' EXIT
for _ in $(seq 1 50); do (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null && break; sleep 0.1; done
TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$port" bash "$here/enroll-tpm.sh"
