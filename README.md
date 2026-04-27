# THM_Linux-Security-Monitoring

## Table of Contents
1. [Linux Logging for SOC](#linux-logging-for-soc)
2. [Linux Threat Detection 1](#linux-threat-detection-1)

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