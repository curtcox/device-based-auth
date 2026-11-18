#!/usr/bin/env bash
# A Linux PC with a TPM 2.0: keep the device key inside the TPM, prove it with EK credential
# activation, enroll, then call the API. Every signature, the enrollment request's and each
# DPoP proof's, is made by the TPM; the private key never exists outside it.
#
# Needs tpm2-tools 5, openssl, curl and jq, and access to the TPM (/dev/tpmrm0, usually the "tss"
# group; or set TPM2TOOLS_TCTI).
#
#   DBA_ORIGIN=http://localhost:8787 bash docs/samples/tpm/enroll-tpm.sh
set -euo pipefail
origin="${DBA_ORIGIN:-https://devicebasedauth.org}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

b64() { openssl base64 -A; }
b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
# Without a resource manager (abrmd or /dev/tpmrm0) the TPM keeps every object loaded; free them.
flush() { tpm2_flushcontext -t >/dev/null 2>&1 || true; }
post() { curl -sS --fail-with-body -H 'Content-Type: application/json' -X POST "$origin$1" --data-binary @-; }

# 1. Keys. The endorsement key (EK) has a certificate from the TPM's manufacturer; the attestation
#    key (AK) is restricted, so the TPM uses it only to sign what it generated itself; the device key
#    is a P-256 signing key generated in the TPM that cannot leave it.
tpm2_createek -c ek.ctx -G rsa -u ek.pub >/dev/null; flush
tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa -u ak.pub -n ak.name >/dev/null; flush
tpm2_createprimary -C o -g sha256 -G ecc -c srk.ctx >/dev/null; flush
tpm2_create -C srk.ctx -G ecc256:ecdsa-sha256 -u key.pub -r key.priv \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' >/dev/null; flush
tpm2_load -C srk.ctx -u key.pub -r key.priv -c key.ctx >/dev/null; flush
tpm2_certify -c key.ctx -C ak.ctx -g sha256 -o certify.bin -s certify.sig >/dev/null; flush
tpm2_nvread 0x01c00002 -o ek.crt 2>/dev/null   # the RSA EK certificate

# The device key as a JWK, and its RFC 7638 thumbprint.
point() { tpm2_print -t TPM2B_PUBLIC key.pub | awk -v k="$1:" '$1 == k { print $2 }'; }
hex_b64u() { printf '%b' "$(sed 's/../\\x&/g')" | b64u; }
x="$(point x | hex_b64u)"; y="$(point y | hex_b64u)"
jwk="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$x\",\"y\":\"$y\"}"
echo "Device key thumbprint: $(printf %s "$jwk" | openssl dgst -sha256 -binary | b64u)"

# A compact ES256 JWS signed by the TPM. tpm2_sign writes DER; JOSE wants r ‖ s, 32 bytes each.
sign_jws() {
  local input; input="$(printf %s "$1" | b64u).$(printf %s "$2" | b64u)"
  printf %s "$input" > input.bin
  tpm2_sign -c key.ctx -g sha256 -f plain -o sig.der input.bin; flush
  local rs; rs="$(openssl asn1parse -inform DER -in sig.der | awk -F: '/INTEGER/ { printf "%064s", $NF }' | tr ' ' 0)"
  echo "$input.$(printf %s "$rs" | hex_b64u)"
}

# 2. Prove the key is in a genuine TPM: the service checks the EK certificate, the AK and its
#    certify, and wraps a secret only this TPM can unwrap.
challenge="$(post /api/v1/enrollments/attestation-challenge < /dev/null | jq -r .challenge)"
echo "Attestation challenge: $challenge"
jq -n --arg challenge "$challenge" --arg ek "$(b64 < ek.crt)" --arg ak "$(b64 < ak.pub)" --arg key "$(b64 < key.pub)" \
  --arg info "$(b64 < certify.bin)" --arg sig "$(b64 < certify.sig)" \
  '{challenge: $challenge, ek_certificate: $ek, ak_pub_area: $ak, pub_area: $key, cert_info: $info, sig: $sig}' \
  | post /api/v1/enrollments/tpm-activation > activation.json
echo "TPM manufacturer check passed; activating"
jq -r .credential_blob activation.json | openssl base64 -d -A > credential.blob
tpm2_startauthsession --policy-session -S session.ctx >/dev/null
tpm2_policysecret -S session.ctx -c e >/dev/null   # the EK's policy: endorsement authorization
tpm2_activatecredential -c ak.ctx -C ek.ctx -i credential.blob -o secret.bin -P session:session.ctx >/dev/null
tpm2_flushcontext session.ctx; flush

# 3. Enroll, with the activation as the key's attestation, and wait for the owner's approval.
payload="$(jq -cn --argjson iat "$(date +%s)" --arg challenge "$challenge" --arg activation "$(jq -r .activation activation.json)" --arg secret "$(b64 < secret.bin)" \
  '{iat: $iat, aud: ["hashbin.org"], grants: [{actions: ["hashbin:content:write"], require: {attestation: "hardware"}}],
    device: {name: "TPM sample", kind: "desktop", key_protection: "tpm"},
    attestation: {format: "tpm-ek", challenge: $challenge, activation: $activation, secret: $secret}}')"
request="$(sign_jws "{\"alg\":\"ES256\",\"typ\":\"dba-enroll+jwt\",\"jwk\":$jwk}" "$payload")"
jq -n --arg request "$request" '{request: $request}' | post /api/v1/enrollments > start.json
echo "Ask the account owner to approve this device:"
jq -r .approval_url start.json
poll_url="$(jq -r .poll_url start.json)"
for _ in $(seq 1 100); do
  sleep "$(jq -r .interval start.json)"
  curl -sS --fail-with-body "$poll_url" > poll.json
  case "$(jq -r .status poll.json)" in
    approved) break ;;
    pending) ;;
    *) echo "Enrollment $(jq -r .status poll.json)" >&2; exit 1 ;;
  esac
done
credential="$(jq -r .credential poll.json)"
jq -R 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .device.attestation' <<< "$credential" \
  | jq -r '"Approved. Attested: \(.security_level) (\(.tpm_manufacturer))"'

# 4. Call the API: a DPoP proof per request, signed by the TPM.
url="$origin/api/v1/whoami"
ath="$(printf %s "$credential" | openssl dgst -sha256 -binary | b64u)"
proof="$(sign_jws "{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":$jwk}" \
  "$(jq -cn --arg jti "$(openssl rand -hex 16)" --arg htu "$url" --arg ath "$ath" --argjson iat "$(date +%s)" '{jti: $jti, htm: "GET", htu: $htu, iat: $iat, ath: $ath}')")"
curl -sS --fail-with-body "$url" -H "Authorization: DBA $credential" -H "DPoP: $proof" \
  | jq -r '"whoami: account \(.account), device \(.device_id)", (.descriptions[] | " - \(.)")'
