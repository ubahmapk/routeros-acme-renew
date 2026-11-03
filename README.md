# routeros-acme-renew

Keep a Let's Encrypt certificate on a MikroTik RouterOS `www-ssl` service, using the ACME **DNS-01** challenge with **Amazon Route 53**. The router never has to be reachable from the internet.

RouterOS's built-in ACME client only supports HTTP-01. This tool runs on a machine you control (a laptop, say), gets the certificate with [lego](https://go-acme.github.io/lego/), pushes it to the router over SSH, and checks that the router is really serving it.

## What a run does

1. **Reachability.** If the router's name does not resolve, or its HTTPS and SSH ports do not answer from where you are, it prints a message and exits `0`. Nothing is touched. This makes it safe to call from a daily script that sometimes runs away from home.
2. **Age check.** It reads the certificate `www-ssl` is serving. A production Let's Encrypt certificate younger than `--renew-days` (default 60) means it stops there. Anything else (older, self-signed, staging) is renewed.
3. **Renew and replace.** lego issues the certificate. The tool uploads it, imports it, points `www-ssl` at it, and reconnects to confirm the router serves the new certificate's fingerprint. If it does not, `www-ssl` is switched back to the previous certificate and the run fails (exit `1`). Only after that check passes are the older certificates this tool created removed from the router.

A fresh certificate left on disk by an earlier run that failed during deployment is reused instead of requesting another one, which keeps you clear of Let's Encrypt rate limits.

## Requirements

- macOS or Linux with [`uv`](https://docs.astral.sh/uv/), `ssh` and `scp`
- [`lego`](https://go-acme.github.io/lego/) v5 (`brew install lego`)
- A Route 53 public hosted zone for your domain
- A RouterOS user that can log in with an SSH key
- Optional: [1Password CLI](https://developer.1password.com/docs/cli/) to supply the AWS keys

The script declares its own Python dependencies (typer, pydantic, arrow, cryptography), so `uv` installs them on first run.

## Setup

**1. IAM user for Route 53.** Create a dedicated user with only this policy, and replace `ZONEID` with your hosted zone ID:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["route53:ListHostedZonesByName", "route53:GetChange"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"],
      "Resource": "arn:aws:route53:::hostedzone/ZONEID"
    }
  ]
}
```

**2. RouterOS user.** Create a user for the automation and install your public key. The group needs enough rights to transfer files, import certificates and change `/ip service`; the policy list below is a starting point, so widen it if RouterOS reports a permission error.

```
/user group add name=acme policy=ssh,ftp,read,write,policy,sensitive
/user add name=acme group=acme password="<long random>"
/user ssh-keys import public-key-file=acme.pub user=acme
```

**3. Credentials.** Copy `example.env` to a private location, fill in your values, and store the two AWS keys in 1Password. The tool only needs `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in its environment, so any method that provides them works.

**4. The router's name must resolve** to its LAN address on your network (a local DNS record or split-horizon entry). It does not need to resolve from the internet.

## Usage

```sh
op run --env-file ~/.config/routeros-acme-renew/router.env -- ./routeros_acme_renew.py
```

Check the decision first without changing anything:

```sh
op run --env-file ... -- ./routeros_acme_renew.py --dry-run
```

Rehearse against the Let's Encrypt staging CA before using the real one. This installs an untrusted staging certificate, which the next normal run replaces automatically:

```sh
op run --env-file ... -- ./routeros_acme_renew.py --staging --force
```

From a daily update script:

```zsh
if [[ -x $(command -v routeros_acme_renew.py) ]] && [[ -x $(command -v op) ]]; then
  op run --env-file ~/.config/routeros-acme-renew/router.env -- routeros_acme_renew.py
fi
```

### Options

| Option | Env var | Default | |
| --- | --- | --- | --- |
| `--host` | `ROUTER_HOST` | required | Router FQDN |
| `--ssh-user` | `ROUTER_SSH_USER` | required | RouterOS SSH user |
| `--email` | `ACME_EMAIL` | required | Contact address registered with the CA |
| `--renew-days` | | `60` | Renew when the served certificate is this old |
| `--https-port` / `--ssh-port` | | `443` / `22` | Ports to check and use |
| `--state-dir` | `ROUTEROS_ACME_STATE_DIR` | `~/.local/share/routeros-acme-renew` | lego account, keys and certificates |
| `--staging` | | off | Use the Let's Encrypt staging CA |
| `--force` | | off | Renew regardless of age |
| `--dry-run` | | off | Report the decision and stop |

Exit codes: `0` for success or a deliberate skip (unreachable router, certificate still fresh), `1` for an error.

## Security notes

- The AWS keys are read from the environment and are never written to disk or printed by this tool.
- lego keeps the ACME account key and the certificate private key under `--state-dir` (directory mode `0700`). Treat that directory as secret.
- `--host` and `--ssh-user` are validated before they reach `ssh`, so a value cannot be turned into an ssh option.
- Staging and production state are kept in separate subdirectories, so a staging certificate is never deployed as a real one.
- Only certificates whose names start with `acme-` (created by this tool) are ever removed from the router.

## Status

Unit tests cover the decision logic, validation, key matching and RouterOS output parsing (`uv run pytest`). The skip and validation paths have been exercised from the command line. The issue-and-deploy path has not yet been run end to end against Let's Encrypt and a real router, so run `--staging --force` first. Details worth confirming on your RouterOS version: the permission set for the SSH user, that `scp` is accepted for uploads, and that the imported leaf certificate is named `<file>.crt_0`. The post-switch fingerprint check and automatic rollback exist to catch exactly these problems.

## License

MIT
