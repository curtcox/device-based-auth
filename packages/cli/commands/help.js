/** What `dba help` prints: every command, its options and the files it keeps. */
export const HELP = `dba — device credentials from devicebasedauth.org

Usage: dba [--profile NAME] [--origin URL] <command> [options]

Enroll this machine:
  dba enroll --aud SITE[,SITE] (--action ACTION ... | --grant 'JSON' ...)
             [--name "My laptop"] [--kind cli] [--lifetime SECONDS] [--wait SECONDS]
             [--print-request] [--force] [--key-store auto|os|file|tpm]
      Makes a new P-256 key, asks for a credential and prints a link for the account owner to
      approve. Waits (default 900 s) and saves the credential. All --action values form one
      grant; each --grant adds one (or a JSON list). --print-request only prints the signed
      request (for agents and the MCP server); finish with \`dba import\`.
      The private key never leaves this machine. It is kept in the OS secret store when there
      is one (macOS Keychain; Secret Service via secret-tool on Linux; DPAPI on Windows) and the credential says
      key_protection "os-keychain"; else in a 0600 file, "software". --key-store os refuses to
      fall back to the file, file never tries the OS store (also DBA_KEY_STORE).
      --key-store tpm makes the key inside the TPM 2.0 (needs tpm2-tools and access to
      /dev/tpmrm0, or TPM2TOOLS_TCTI): it can never leave the TPM, which signs every request.
      dba also proves to the server that the key is in a genuine TPM (EK credential
      activation), so the credential says attestation "tpm" and satisfies grants that require
      hardware; key_protection "tpm". \`dba certificate\` cannot export a TPM key.
  dba enroll --token dbae_… [--aud …] [--action …] [--name …]
      Enroll with an enrollment token the owner created for a fleet: no approval link, the
      credential is issued at once. The token's audiences and grants apply unless you narrow
      them. Prefer DBA_ENROLLMENT_TOKEN=dbae_… over --token to keep it out of shell history.

Create an account, or get back into one (no password or sign-in provider):
  dba signup --accept-terms [--deposit 5] [--name …] [--no-recovery-codes] [--wait SECONDS]
      Makes a new key, prints a Stripe Checkout link for the first deposit ($5–$20 in the first
      week), and once it is paid saves a dashboard credential (dba:session) for the new account.
      Prints a recovery sheet (account id and ten one-time codes) unless --no-recovery-codes.
      Interrupted? \`dba signup --resume\`.
  dba recover --account acct_… --code XXXX-XXXX-XXXX
  dba recover --account acct_… [--via gate]       A passkey or another device approves.
  dba recover --email you@example.com             A link to the verified address, then 72 h.
      Puts this machine on the account with a new key after losing every device; for ten
      minutes that counts as a recent sign-in. A wait can be finished with --resume.

Use the credential:
  dba status | whoami [--online] [--json]   What this device may do, in plain English.
  dba headers METHOD URL                    Print Authorization and DPoP headers for one request.
  dba sign METHOD URL                       Print only the DPoP proof.
  dba curl CURL-ARGS...                     Run curl (7.55+) with the headers added (from a private file, not argv).
                                            --dba-wait[=SECONDS] (anywhere among them): while the site
                                            answers 403 gate_pending, send the request again with a
                                            fresh proof until its gates decide (default 300 s; exits 1
                                            if they have not). Prints the final body; no -o, -i, -f.
  dba token --aud SITE                      Print a 10-minute bearer token for SITE:
                                              curl -H "Authorization: Bearer $(dba token --aud hashbin.org)" ...
  dba certificate [--lifetime SECONDS]      Write an X.509 client certificate for this device's key
                                            (client.crt, client.key, ca.crt in the profile
                                            directory) for mTLS: curl --cert … --key …. Valid 1 hour
                                            by default, at most 24; 5 µ$.
  dba renew [--rotate] [--if-due]           Renew the credential (--rotate: move to a new key;
                                            --if-due: only once 2/3 of its lifetime has passed,
                                            for a daily cron job on rarely used devices).
  dba revoke                                Revoke this device's credential and delete its files.

Gates and confirmation:
  dba confirm [--wait SECONDS]              Ask this credential's gates to confirm it is still trusted
                                            (credentials issued with "confirm"). Waits (default 300 s),
                                            saves confirmation.jwt; 12 µ$. headers and curl send it as
                                            DBA-Confirmation and ask for a new one when it is due
                                            (DBA_AUTO_CONFIRM=0: never ask on their own).
  dba approvals [--watch] [--json]          Gate requests this device can answer as a dba-device gate
                                            (its credential needs dba:approvals:answer). --watch keeps
                                            listing new ones every 5 s until Ctrl-C.
  dba approvals allow|deny REQUEST [--entry N] [--number NN]
                                            Answer one. Sign-ins hide their number: type the one shown
                                            where the sign-in waits with --number.
  dba gates [--json]                        The account's gates (DBA_API_KEY with gates:read, or this
                                            device with dba:gates:read).
  dba gates add --kind dba-device --label TEXT --device dev_…
  dba gates add --kind webhook --label TEXT --url https://… --public-jwk JSON
  dba gates test GATE                       Send a webhook gate a signed test message (5 µ$).
  dba gates remove GATE                     Changing gates needs DBA_API_KEY with gates:write (a device
                                            cannot: that needs a recent sign-in). TOTP, security keys,
                                            Duo and Okta Verify are set up on the dashboard's Gates page.

The account:
  dba list [--status active|expired|revoked] [--audience SITE] [--device ID] [--all] [--json]
      Every credential on the account, 50 at a time (--all: every page). Uses DBA_API_KEY (an
      API key with credentials:read) when set, else this device's credential, which then needs
      dba:credentials:read. Each page is a metered read (5 µ$).

Any credential:
  dba inspect CREDENTIAL|- [--json]         Decode it and ask the server about its signature and revocation.
  dba import CREDENTIAL|-                   Save a credential issued for this profile's key.

Renewal:
  headers, sign, curl, token, certificate and status --online renew the credential first once two thirds of
  its lifetime has passed (25 µ$ from the account's balance). If renewal fails they warn and use
  the current credential, which is still valid. Turn this off with --no-renew or DBA_AUTO_RENEW=0.

Options:
  --profile NAME   Keep several devices apart (default "default").
  --no-renew       Never renew automatically.
  --origin URL     Server (default $DBA_ORIGIN, then the origin used at enrollment,
                   then https://devicebasedauth.org).

Files: $DBA_HOME/<profile>/ (default ~/.config/dba/<profile>/): key.json, credential.jwt, config.json.
A key in the OS secret store is listed there under service org.devicebasedauth.dba.
`;
