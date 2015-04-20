## b-scan

A perl script that scans common ports for
any avalaible service banner.

then saves the all found information to 
file named "results".

usage

```
./bscan.pl [ valid network ip / with cidr netmask]
```

Output file example

```
---------------------------------------------------
[+] summary for 192.168.42.70
        Port : 21 : no service detected
        Port : 22 : no service detected
        Port : 23 : no service detected
        Port : 25 : no service detected
        Port : 80 : no service detected
        Port : 443 : no service detected
---------------------------------------------------
[+] summary for 192.168.42.71
        Port : 21 : no service detected
        Port : 22 : SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2
        Port : 23 : Ubuntu 14.04.1 LTSnull
        Port : 25 : no service detected
        Port : 80 : lighttpd/1.4.33
        Port : 443 : no service detected
---------------------------------------------------
[+] summary for 192.168.42.72
        Port : 21 : no service detected
        Port : 22 : no service detected
        Port : 23 : no service detected

```
