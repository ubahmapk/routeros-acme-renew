# routeros-acme-renew

Keep a Let's Encrypt certificate on a MikroTik RouterOS `www-ssl` service, using the ACME **DNS-01** challenge with **Amazon Route 53**. The router never has to be reachable from the internet.

RouterOS's built-in ACME client only supports HTTP-01. This tool runs on a machine you control (a laptop, say), gets the certificate, pushes it to the router, and checks that the router is really serving it. It is pure Python, with no external programs to install:

| Job | Library |
| --- | --- |
| ACME protocol | [`acme`](https://pypi.org/project/acme/) (the library Certbot is built on) |
| DNS challenge records | [`boto3`](https://pypi.org/project/boto3/) (Route 53) |
| Router upload and commands | [`paramiko`](https://pypi.org/project/paramiko/) (SSH and SFTP) |

## What a run does

1. **Reachability.** If the router's name does not resolve, or its HTTPS and SSH ports do not answer from where you are, it prints a message and exits `0`. Nothing is touched. This makes it safe to call from a daily script that sometimes runs away from home.
2. **Age check.** It reads the certificate `www-ssl` is serving. A production Let's Encrypt certificate younger than `--renew-days` (default 60) means it stops there. Anything else (older, self-signed, staging) is renewed.
3. **Issue.** It orders an EC P-256 certificate, publishes the challenge TXT record in Route 53, waits for Route 53 to report it live, lets the CA validate it, then removes the record.
4. **Deploy.** It uploads the certificate and key over SFTP, imports them, points `www-ssl` at the new certificate, and reconnects to confirm the router serves the new certificate's fingerprint. If it does not, `www-ssl` goes back to the previous certificate, the new imports are removed, and the run fails with exit `1`. Only after the check passes are older certificates created by this tool removed from the router.

A fresh certificate left on disk by an earlier run that failed during deployment is reused instead of requesting another one, which keeps you clear of Let's Encrypt rate limits.

### How it treats your DNS

- Route 53 replaces a whole record set when it is updated, so the tool reads the TXT values already at `_acme-challenge.<host>`, adds its own, and later removes only its own. Other values are left alone.
- Each challenge record is written to a small file under the state directory *before* it is created. If a run is killed part-way, the next run removes the leftover.
- If `_acme-challenge.<host>` is a CNAME (validation delegated to another zone), the run stops with an error. That setup is not supported.

## Install

```sh
uv tool install git+https://github.com/ubahmapk/routeros-acme-renew
```

Update later with `uv tool upgrade routeros-acme-renew`, or let an existing `uv tool upgrade --all` do it. For local development, `uv sync` and `uv run routeros-acme-renew --help`.

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

If you set `AWS_HOSTED_ZONE_ID`, the zone lookup is skipped and `ListHostedZonesByName` can be dropped.

**2. RouterOS user.** Create a user for the automation and install your public key. The group needs enough rights to upload files, import certificates and change `/ip service`; the policy list below is a starting point, so widen it if RouterOS reports a permission error.

```
/user group add name=acme policy=ssh,ftp,read,write,policy,sensitive
/user add name=acme group=acme password="<long random>"
/user ssh-keys import public-key-file=acme.pub user=acme
```

**3. Trust the router's SSH host key.** Connect once by hand (`ssh acme@router.example.com`) so the key is in `~/.ssh/known_hosts`. The tool refuses to connect to a host it does not already know. It authenticates with your ssh-agent or keys in `~/.ssh`, or a key file you give with `--ssh-key`.

**4. Credentials.** Copy `example.env` to a private location, fill in your values, and store the two AWS keys in 1Password. boto3 reads `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from the environment, so any method that provides them works.

**5. The router's name must resolve** to its LAN address on your network (a local DNS record or split-horizon entry). It does not need to resolve from the internet.

## Usage

```sh
op run --env-file ~/.config/routeros-acme-renew/router.env -- routeros-acme-renew
```

Check the decision first without changing anything:

```sh
op run --env-file ... -- routeros-acme-renew --dry-run
```

Rehearse against the Let's Encrypt staging CA before using the real one. This installs an untrusted staging certificate, which the next normal run replaces automatically:

```sh
op run --env-file ... -- routeros-acme-renew --staging --force
```

From a daily update script:

```zsh
if [[ -x $(command -v routeros-acme-renew) ]] && [[ -x $(command -v op) ]]; then
  op run --env-file ~/.config/routeros-acme-renew/router.env -- routeros-acme-renew
fi
```

### Options

| Option | Env var | Default | |
| --- | --- | --- | --- |
| `--host` | `ROUTER_HOST` | required | Router FQDN |
| `--ssh-user` | `ROUTER_SSH_USER` | required | RouterOS SSH user |
| `--email` | `ACME_EMAIL` | required | Contact address registered with the CA |
| `--ssh-key` | `ROUTER_SSH_KEY` | agent / `~/.ssh` | SSH private key file |
| `--zone-id` | `AWS_HOSTED_ZONE_ID` | auto-detect | Route 53 hosted zone |
| `--renew-days` | | `60` | Renew when the served certificate is this old |
| `--https-port` / `--ssh-port` | | `443` / `22` | Ports to check and use |
| `--state-dir` | `ROUTEROS_ACME_STATE_DIR` | `~/.local/share/routeros-acme-renew` | ACME account, certificate and key |
| `--staging` | | off | Use the Let's Encrypt staging CA |
| `--force` | | off | Renew regardless of age |
| `--dry-run` | | off | Report the decision and stop |

Exit codes: `0` for success or a deliberate skip (unreachable router, certificate still fresh), `1` for an error.

## Security notes

- AWS credentials come from the environment through boto3 and are never written to disk or printed. Error tracebacks do not include local variables.
- The ACME account key, the certificate private key and the pending-record file live under `--state-dir`, owner-readable only (files `0600`, directories `0700`). Treat that directory as secret.
- The router's SSH host key must already be known. Unknown hosts are rejected, not auto-trusted.
- `--host` and `--ssh-user` are validated before they reach SSH or RouterOS commands.
- Staging and production state are kept in separate subdirectories, so a staging certificate is never deployed as a real one.
- Only certificates whose names start with `acme-` (created by this tool) are ever removed from the router.
- The ACME account is registered with `--email` and accepts the CA's terms of service the first time it is created.

## Status

49 unit tests cover the renewal decision, input validation, Route 53 record handling (against botocore's stubber), the ACME challenge flow (with real `acme` message objects and a fake CA), deployment including rollback, the SSH wrapper (against a fake paramiko client), and the command line skip and error paths.

Not yet run: the whole thing end to end against Let's Encrypt, Route 53 and a real router. Run `--staging --force` first. Details worth confirming on your RouterOS version: the permission set for the SSH user, SFTP uploads into the router's root directory, that the imported leaf certificate is named `<file>.crt_0`, and that RouterOS error text is caught by the patterns in `router.py`. The post-switch fingerprint check and automatic rollback exist to catch exactly these problems.

## License

MIT
