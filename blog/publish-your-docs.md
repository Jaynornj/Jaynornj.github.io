# Locked and Loaded: Defending the Network in a Red vs Blue Showdown!

In our recent **six-hour Red Team vs Blue Team event**, we faced the challenge of securing systems like **Rocky Linux 9, Ubuntu 20, Windows Server 2022**, and **Windows Server 2016**, all while enduring continuous attacks. Each system was running critical services such as **RDP, SSH, DNS, web servers, MySQL, vsftpd**, and more, under constant assault from the red team.

Within minutes of the competition starting, we realized that **two red team users had already infiltrated each of our Linux machines**! To respond quickly, we deployed a **lockdown script** to:

* Analyze the system's distribution and version
* Check for updates and running services
* Review users, groups, and their privileges
* Ensure that firewalls were active
* Install crucial tools like **fail2ban, firewalld, lynis, clamAV**, and more

We hardened **SSH** by disabling root login, enforcing SSH key access, and disabling password logins. To lighten the mood, we added a fun banner for the red team. While **SSH hardening** went smoothly, we encountered problems with **vsftpd**, which opened unexpected ports. This was a tough learning curve for us.

A key takeaway was that **hands-on experience** far outweighs theory in these competitions. Our failure to test **vsftpd** beforehand was a rookie mistake, highlighting the importance of practice. Despite these challenges, we managed to complete our first task from the "CEO" without any issues.

The first hour also saw our **Windows manager struggling to access the system**, which further proved the need for testing and practice using **VMs** before a competition to avoid surprises.

As the event continued, the attacks ramped up. My **vsftpd service on Rocky Linux** was down for two hours due to firewall issues, while **SSH on Ubuntu** was compromised. It took me an hour to regain control because the red team had modified firewall rules, banned my IP, and changed **fail2ban settings**. This was a clever and unexpected move. After regaining access, I launched into **threat hunting** to detect persistence. I used **snoopy** and **pspy64**, tools that use the **LD\_PRELOAD** library, and was able to intercept their **C2 communications**. The red team was attempting to manipulate our firewall and **fail2ban** configurations, so I purged **fail2ban**, which was causing more harm than good. I blocked unauthorized ports and removed their C2, which was using **HTTP on port 8080**, a method I recognized.

Later, I discovered they had deployed a **reverse shell** in some **Java config files**. Since **Java** wasn’t necessary, I purged it from the **Ubuntu machine**. Thankfully, my **Rocky Linux system** remained stable, aside from the **vsftpd issues**. However, on **Ubuntu**, I found rogue users in **/etc/passwd** with names like "jenkis," "systemLog," and "SSSH," which were clearly placed there by the red team. They even used some obvious usernames like "joe," "ap0kalypse," and "nobody."

Despite the rocky start, in the **final hour**, we managed to get all systems back online. Our **Windows admin** resolved the earlier issues, which brought relief after the chaos of the initial hours. The last **30 minutes** were filled with constant attacks, and during the final **10 minutes**, the red team even managed to take down my **MySQL server** by modifying **/etc/passwd permissions**.

Although we didn't secure the win, the event was an invaluable learning experience. We took extensive notes and completed our **first Plinko event as a team** from FSCJ, and I’m incredibly proud of those who participated. For many, it was their first experience in a hands-on event like this.

On the final day, I had the opportunity to help the **Plinko team** as part of the **black team**, responding to technical questions from competitors. This gave me a unique perspective on the competition and allowed me to see more tactics used by the **red team** from the other side. It was an eye-opening experience to view the competition from this angle, adding further to the overall learning experience.

A huge thanks to the **UCF Plinko organizers** for putting together such an outstanding event. As always, they never disappoint!

For future students, this is the best way to gain practical experience. The competition's infrastructure closely resembled that of a real company. The injects we received from the "CEO" were akin to real-life tasks, and the reports we submitted were similar to those a **sysadmin** would handle in a real-world environment.

Moreover, we had the chance to network with recruiters and companies such as **Lockheed Martin, ThreatLocker, FPL Energy, Naval Nuclear Laboratory**, and others during the event at UCF. They were open to our questions, provided feedback on our resumes, and offered valuable advice for internships and future careers.

In conclusion, I encourage all students to get involved in these events. They offer real-world scenarios and allow you to gain hands-on experience while still a student. If you have any questions or need guidance, feel free to reach out.

Also, stay tuned! The **Tallahassee trip** is coming up soon, and our team will be making the official announcement in the next few days!

**Let’s go, FSCJ Cyber Security Club!**

<figure><img src="../.gitbook/assets/SSH BANNER.png" alt=""><figcaption></figcaption></figure>

