# @devicebasedauth/cli

`dba`: enroll a machine with [devicebasedauth.org](https://devicebasedauth.org), then use its
device-bound credential from the command line. The private key is made on this machine and never
leaves it: it is kept in the OS secret store where there is one (macOS Keychain, Secret Service on
Linux, DPAPI on Windows), in a TPM 2.0 with `--key-store tpm`, or else in a `0600` file.

```sh
npm install -g @devicebasedauth/cli     # Node 22+
```

```sh
dba enroll --aud hashbin.org --action hashbin:content:write --name "My laptop"
# prints a link for the account owner to approve, then saves the credential
dba status                                  # (or whoami) what this device may do, in plain English
dba curl -sS https://hashbin.org/api/...    # curl with Authorization and DPoP headers added
dba headers POST https://hashbin.org/api/content   # or `dba sign` for the DPoP proof alone
dba token --aud hashbin.org                 # a 10-minute bearer token for plain curl
dba revoke
```

Other commands: `signup` and `recover` (an account with no password or sign-in provider),
`renew`, `certificate` (an X.509 client certificate for mTLS), `confirm`, `approvals` and `gates`
(gates and periodic confirmation), `list`, `inspect` and `import`. `dba --help` describes each.

Profiles live in `$DBA_HOME/<profile>/` (default `$XDG_CONFIG_HOME/dba/<profile>/`, else
`~/.config/dba/<profile>/`); `--profile NAME` keeps several devices apart and `--origin URL` (or `DBA_ORIGIN`) picks the server.
`headers`, `sign`, `curl`, `token`, `certificate` and `status --online` renew the credential once
two thirds of its lifetime has passed (`--no-renew` or `DBA_AUTO_RENEW=0` turns that off). Other
environment variables: `DBA_KEY_STORE` (default for `--key-store`), `DBA_ENROLLMENT_TOKEN` (in
place of `enroll --token`), `DBA_API_KEY` (an API key for `list` and `gates` instead of the
device's credential) and `DBA_AUTO_CONFIRM=0` (`headers` and `curl` never ask for a confirmation
on their own). Runnable
examples, executed in CI: [`docs/samples/enroll-and-call.sh`](https://github.com/curtcox/device-based-auth/blob/main/docs/samples/enroll-and-call.sh),
[`signup-and-recover.sh`](https://github.com/curtcox/device-based-auth/blob/main/docs/samples/signup-and-recover.sh),
[`approve-from-cli.sh`](https://github.com/curtcox/device-based-auth/blob/main/docs/samples/approve-from-cli.sh),
[`os-keychain.sh`](https://github.com/curtcox/device-based-auth/blob/main/docs/samples/os-keychain.sh)
and [`tpm/dba-cli.sh`](https://github.com/curtcox/device-based-auth/blob/main/docs/samples/tpm/dba-cli.sh).
