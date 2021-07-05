# shocker, flow

## prev enum

```sh
sudo nmap -sS -sC -sV -oA ./nmap/full_sS -O -p- 192.168.0.1
  # 80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
  # 2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0
```

## searchsploit

```sh
searchsploit apache 2.4.18

  # reject
  # Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                          | php/remote/29290.c
  # Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                        | php/remote/29316.py
  # Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                                      | multiple/dos/26710.txt
  # Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal                                                      | linux/webapps/39642.txt
  # Apache Tomcat < 5.5.17 - Remote Directory Listing                                                                        | multiple/remote/2061.txt
  # Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                                      | unix/remote/14489.c
  # Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                                | multiple/remote/6229.txt
  # Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)             | windows/webapps/42953.txt
  # Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)             | jsp/webapps/42966.py
  # Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                             | linux/dos/36906.txt
  # Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution                                         | linux/remote/34.pl

  # hold
  # Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                     | unix/remote/21671.c
  # Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                               | unix/remote/764.c
  # Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                               | unix/remote/47080.c

  # try
  # Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation                                    | linux/local/46676.php
  # Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak                                                                         | linux/webapps/42745.py
```

```sh
cdee
cp /usr/share/exploitdb/exploits/linux/local/46676.php ~/assets/shocker/46665.php
  # Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation
cp /usr/share/exploitdb/exploits/linux/webapps/42745.py ~/assets/shocker/42745.py
  # Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak
cda
```

```sh
python3 42745.py shocker
  # no result
```

## gobuster

```sh
dict="/usr/share/wordlists/dirb/common.txt"
ls -lah $dict                                    # 36KB
gobuster dir -u http://shocker/ -w $dict -t 20 -e -x php,asp,json,aspx
  # 5min
  # find /cgi-bin/ (status 403)

gobuster dir -u http://shocker/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -t 20 -e -x cgi,sh,pl,py,rb,php
  # 5min
  # find /user.sh (status 200)
```
