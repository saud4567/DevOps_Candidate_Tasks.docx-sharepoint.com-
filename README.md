                                                                                 Task-1
Monitoring system resource for a proxy server

1. Introduction
Briefly introduce the purpose of the script. Mention that it is designed to monitor various system resources in real-time and present them in a dashboard format. Highlight the key features, such as real-time updates, the ability to view specific parts of the dashboard using command-line switches, and customization options.
2. Step-by-Step Command Execution
Command 1: Display Top 10 CPU and Memory Consuming Processes

Command: ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 11
Explanation: This command lists the top 10 processes consuming the most CPU and memory.
Example Output: Include a sample output.
Command 2: Display Network Statistics

Command:
ss -s | grep "TCP:" (Number of concurrent connections)
netstat -i | awk '{ if ($1 != "Kernel" && $1 != "Iface" && $1 != "") print $1, "drop:", $4}' (Packet drops)
ifconfig | grep 'RX bytes' | awk '{print $2, $6}' (MB in and out)
Explanation: These commands provide network statistics, including concurrent connections, packet drops, and data transfer.
Example Output: Include sample outputs.
Command 3: Display Disk Space Usage

Command: df -h | awk '$5 >= 80 {print $0}'
Explanation: This command shows disk space usage by mounted partitions, highlighting those using more than 80% of the space.
Example Output: Include a sample output.
Command 4: Display System Load Average

Command:
uptime (Current load average)
mpstat (CPU usage breakdown)
Explanation: These commands show the system's load average and a breakdown of CPU usage.
Example Output: Include sample outputs.
Command 5: Display Memory Usage

Command:
free -m (Total used and free memory)
free -m | grep "Swap" (Swap memory usage)
Explanation: These commands display the system's memory and swap usage.
Example Output: Include sample outputs.
Command 6: Display Number of Active Processes

Command:
ps aux | wc -l (Number of active processes)
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6 (Top 5 processes by CPU and memory usage)
Explanation: These commands provide information about the number of active processes and the top 5 resource-consuming processes.
Example Output: Include sample outputs.
Command 7: Monitor Essential Services

Command:
systemctl is-active --quiet sshd && echo "sshd is running" || echo "sshd is not running"
systemctl is-active --quiet nginx && echo "nginx is running" || echo "nginx is not running"
systemctl is-active --quiet apache2 && echo "apache2 is running" || echo "apache2 is not running"
systemctl is-active --quiet iptables && echo "iptables is running" || echo "iptables is not running"
Explanation: These commands check if essential services like sshd, nginx, apache2, and iptables are running.
Example Output: Include a sample output.
3. Merging Commands into a Script
Explain how you combined all the individual commands into a single bash script.
Script Creation
Create a script file: nano monitor.sh
Copy the merged commands into this file.
Save and exit.
4. Granting Execution Permissions
Command: chmod +x monitor.sh
Explanation: This command grants execution permissions to the script file, allowing it to be run.
5. Running the Script
Command: ./monitor.sh
Explanation: This command executes the script. Mention any specific options or switches that can be used.
Usage:
To view the full dashboard: ./your_script.sh
To view specific sections:
CPU and Memory: ./your_script.sh -c
Network: ./your_script.sh -n
Disk Space: ./your_script.sh -d
Load Average: ./your_script.sh -l
Memory: ./your_script.sh -a
Essential Services: ./your_script.sh -s
after run the script the output i got 
root@ip-172-31-47-154:~# ./monitor_script.sh 
Top 10 CPU and Memory consuming processes:
    PID    PPID CMD                         %MEM %CPU
      1       0 /sbin/init                   1.3  0.5
    561       1 /snap/amazon-ssm-agent/7993  1.8  0.0
    137       1 /usr/lib/systemd/systemd-jo  1.4  0.0
    585       1 /usr/lib/snapd/snapd         3.0  0.0
    185       1 /usr/lib/systemd/systemd-ud  0.8  0.0
    339       1 /usr/lib/systemd/systemd-re  1.3  0.0
    929       1 /sbin/agetty -o -p -- \u --  0.1  0.0
    542       1 /usr/bin/python3 /usr/bin/n  2.1  0.0
      9       2 [kworker/0:1-events]         0.0  0.0
    785       1 /usr/bin/python3 /usr/share  2.3  0.0

Network statistics:
Number of concurrent connections to the server:
8
Packet drops:
MB in and out:
10283 100
10283 100
165365 1093
133630 1104

Disk space usage by mount partition:

Current load average for the system:
 04:50:06 up 12 min,  1 user,  load average: 0.00, 0.01, 0.02
CPU usage breakdown (usr, system, idle, etc):
Linux 6.8.0-1014-aws (ip-172-31-47-154)         08/23/24        _x86_64_        (1 CPU)

04:50:06     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
04:50:06     all    0.96    0.01    0.57    0.19    0.00    0.03    1.02    0.00    0.00   97.22

Memory usage:
               total        used        free      shared  buff/cache   available
Mem:             957         322         529           1         256         635
Swap:              0           0           0
Swap memory usage:
Swap:              0           0           0

Number of active processes:
113
Top 5 processes by CPU and memory usage:
    PID    PPID CMD                         %MEM %CPU
      1       0 /sbin/init                   1.3  0.5
    561       1 /snap/amazon-ssm-agent/7993  1.8  0.0
    137       1 /usr/lib/systemd/systemd-jo  1.4  0.0
    585       1 /usr/lib/snapd/snapd         3.0  0.0
    185       1 /usr/lib/systemd/systemd-ud  0.8  0.0

Monitoring essential services (sshd, nginx/apache, iptables):
sshd is running
nginx is running
apache2 is running
iptables is running


                                                                          Task-2

Documentation: Security Audit and Hardening Script Creation
1. Introduction
This document provides a detailed explanation of the steps taken to create, test, and execute a bash script for automating security audits and hardening Linux servers. The script is designed to be reusable and modular, ensuring it can be easily deployed across multiple servers to meet stringent security standards.

2. Step-by-Step Command Execution
Before creating the script, I ran each command individually to ensure its correctness and functionality. This section outlines the commands used and their purpose.

2.1. User and Group Checks
List all users and groups:

cat /etc/passwd
cat /etc/group
Check for users with UID 0 (root privileges):

awk -F: '($3 == "0") {print}' /etc/passwd
Identify users without passwords or with weak passwords:

sudo cat /etc/shadow | awk -F: '($2=="*" || $2=="!" || length($2)<8) {print $1}'
2.2. File and Directory Scans
Scan for world-writable files and directories:

find / -perm -o+w -type f -exec ls -l {} \;
Check .ssh directory permissions:

find /home -type d -name ".ssh" -exec chmod 700 {} \;
Report files with SUID/SGID bits set:

find / -perm /6000 -type f -exec ls -ld {} \;
2.3. Service Audits
List all running services:

systemctl list-units --type=service --state=running
Check for unnecessary or unauthorized services:

systemctl list-unit-files | grep enabled
Ensure critical services are properly configured:

systemctl status sshd
systemctl status iptables
2.4. Firewall Configuration
Verify firewall status:

sudo ufw status
Check for IP forwarding:

sysctl net.ipv4.ip_forward
2.5. IP and Network Checks
Identify public and private IPs:

ip a | grep inet
2.6. Security Updates
Check for available security updates:

sudo apt update && sudo apt list --upgradable
2.7. Server Hardening
Disable IPv6 (if not required):

sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
Secure the bootloader:

sudo grub-mkpasswd-pbkdf2
3. Merging Commands into a Script
After verifying the correctness of each command, I proceeded to merge them into a single script file.

3.1. Script Creation
Creating the script file:

nano security_audit_hardening.sh
Merging the commands: Each of the commands listed above was placed in the script in a logical sequence, with appropriate comments to explain their function.
3.2. Adding Execution Permissions
Granting execution permissions:

chmod +x security_audit_hardening.sh
4. Running the Script
Once the script was complete and executable, I ran it to perform the full security audit and hardening process.

4.1. Execution
Running the script:

sudo ./security_audit_hardening.sh
4.2. Review of Output
After running the script, I reviewed the generated report to ensure that all security checks and hardening measures were correctly applied.

output
root@ip-172-31-47-154:~# ./security_audit_hardening.sh 
Listing all users and groups...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
syslog:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin
uuidd:x:103:103::/run/uuidd:/usr/sbin/nologin
tss:x:104:104:TPM software stack,,,:/var/lib/tpm:/bin/false
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:106:1::/var/cache/pollinate:/bin/false
tcpdump:x:107:108::/nonexistent:/usr/sbin/nologin
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:990:990:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
polkitd:x:989:989:User for polkitd:/:/usr/sbin/nologin
ec2-instance-connect:x:109:65534::/nonexistent:/usr/sbin/nologin
_chrony:x:110:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:ubuntu
floppy:x:25:
tape:x:26:
sudo:x:27:ubuntu
audio:x:29:
dip:x:30:ubuntu
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:999:
systemd-network:x:998:
crontab:x:997:
systemd-timesync:x:996:
input:x:995:
sgx:x:994:
kvm:x:993:
render:x:992:
messagebus:x:101:
syslog:x:102:
systemd-resolve:x:991:
uuidd:x:103:
tss:x:104:
lxd:x:105:ubuntu
_ssh:x:106:
rdma:x:107:
tcpdump:x:108:
landscape:x:109:
fwupd-refresh:x:990:
polkitd:x:989:
admin:x:110:
netdev:x:111:
_chrony:x:112:
ubuntu:x:1000:
ssl-cert:x:113:
Checking for users with UID 0 (root privileges)...
root
Checking for users without passwords or with weak passwords...
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
_apt
nobody
Scanning for world-writable files and directories...
/var/tmp
/var/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-systemd-resolved.service-qHKCRN/tmp
/var/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-polkit.service-jpcP1c/tmp
/var/tmp/cloud-init
/var/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-systemd-logind.service-DwykYS/tmp
/var/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-apache2.service-XwAlIO/tmp
/var/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-ModemManager.service-hFc86A/tmp
/var/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-chrony.service-FrAuxQ/tmp
/var/crash
/tmp
/tmp/.XIM-unix
/tmp/.X11-unix
/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-systemd-resolved.service-GnqseC/tmp
/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-systemd-logind.service-mPwbFF/tmp
/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-apache2.service-MpTaio/tmp
/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-polkit.service-Yjcmof/tmp
/tmp/.font-unix
/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-ModemManager.service-XND0mC/tmp
/tmp/.ICE-unix
/tmp/systemd-private-f5f35d2ec11f4e13b42989d4572aa462-chrony.service-5FBi5s/tmp
Checking .ssh directories for secure permissions...
Reporting files with SUID/SGID bits set...
find: ‘/proc/1739/task/1739/fdinfo/6’: No such file or directory
find: ‘/proc/1739/fdinfo/5’: No such file or directory
-rwsr-xr-x 1 root root 40664 Apr  9 07:01 /usr/bin/newgrp
-rwxr-sr-x 1 root crontab 39664 Mar 31 00:06 /usr/bin/crontab
-rwxr-sr-x 1 root _ssh 309688 Jul  9 11:31 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 72792 Apr  9 07:01 /usr/bin/chfn
-rwsr-xr-x 1 root root 39296 Apr  8 15:57 /usr/bin/fusermount3
-rwxr-sr-x 1 root shadow 27152 Apr  9 07:01 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 72184 Apr  9 07:01 /usr/bin/chage
-rwsr-xr-x 1 root root 44760 Apr  9 07:01 /usr/bin/chsh
-rwsr-xr-x 1 root root 55680 Apr  9 14:02 /usr/bin/su
-rwsr-xr-x 1 root root 76248 Apr  9 07:01 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 51584 Apr  9 14:02 /usr/bin/mount
-rwsr-xr-x 1 root root 277936 Apr  8 14:50 /usr/bin/sudo
-rwsr-xr-x 1 root root 39296 Apr  9 14:02 /usr/bin/umount
-rwsr-xr-x 1 root root 64152 Apr  9 07:01 /usr/bin/passwd
-rwxr-sr-x 1 root utmp 14488 Apr  8 16:08 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwsr-xr-x 1 root root 342632 Jul  9 11:31 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 154824 Jul 26 02:32 /usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root messagebus 34960 Apr  8 14:38 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 18736 Apr  3 18:26 /usr/lib/polkit-1/polkit-agent-helper-1
-rwxr-sr-x 1 root shadow 26944 May  2 22:20 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 31040 May  2 22:20 /usr/sbin/unix_chkpwd
-rwsr-xr-x 1 root root 135960 Apr 24 16:45 /snap/snapd/21759/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /snap/core18/2829/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/2829/bin/ping
-rwsr-xr-x 1 root root 44664 Nov 29  2022 /snap/core18/2829/bin/su
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /snap/core18/2829/bin/umount
-rwxr-sr-x 1 root shadow 34816 Feb  2  2023 /snap/core18/2829/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Feb  2  2023 /snap/core18/2829/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 71816 Nov 29  2022 /snap/core18/2829/usr/bin/chage
-rwsr-xr-x 1 root root 76496 Nov 29  2022 /snap/core18/2829/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Nov 29  2022 /snap/core18/2829/usr/bin/chsh
-rwxr-sr-x 1 root shadow 22808 Nov 29  2022 /snap/core18/2829/usr/bin/expiry
-rwsr-xr-x 1 root root 75824 Nov 29  2022 /snap/core18/2829/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Nov 29  2022 /snap/core18/2829/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Nov 29  2022 /snap/core18/2829/usr/bin/passwd
-rwxr-sr-x 1 root lxd 362640 Mar 30  2022 /snap/core18/2829/usr/bin/ssh-agent
-rwsr-xr-x 1 root root 149080 Apr  4  2023 /snap/core18/2829/usr/bin/sudo
-rwxr-sr-x 1 root tty 30800 Sep 16  2020 /snap/core18/2829/usr/bin/wall
-rwsr-xr-- 1 root uuidd 42992 Oct 25  2022 /snap/core18/2829/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar 30  2022 /snap/core18/2829/usr/lib/openssh/ssh-keysign
Listing all running services...
  UNIT                                           LOAD   ACTIVE SUB     DESCRIPTION                                                   
  acpid.service                                  loaded active running ACPI event daemon
  apache2.service                                loaded active running The Apache HTTP Server
  chrony.service                                 loaded active running chrony, an NTP client/server
  cron.service                                   loaded active running Regular background program processing daemon
  dbus.service                                   loaded active running D-Bus System Message Bus
  getty@tty1.service                             loaded active running Getty on tty1
  ModemManager.service                           loaded active running Modem Manager
  multipathd.service                             loaded active running Device-Mapper Multipath Device Controller
  networkd-dispatcher.service                    loaded active running Dispatcher daemon for systemd-networkd
  nginx.service                                  loaded active running A high performance web server and a reverse proxy server
  polkit.service                                 loaded active running Authorization Manager
  rsyslog.service                                loaded active running System Logging Service
  serial-getty@ttyS0.service                     loaded active running Serial Getty on ttyS0
  snap.amazon-ssm-agent.amazon-ssm-agent.service loaded active running Service for snap application amazon-ssm-agent.amazon-ssm-agent
  snapd.service                                  loaded active running Snap Daemon
  ssh.service                                    loaded active running OpenBSD Secure Shell server
  systemd-journald.service                       loaded active running Journal Service
  systemd-logind.service                         loaded active running User Login Management
  systemd-networkd.service                       loaded active running Network Configuration
  systemd-resolved.service                       loaded active running Network Name Resolution
  systemd-udevd.service                          loaded active running Rule-based Manager for Device Events and Files
  udisks2.service                                loaded active running Disk Manager
  unattended-upgrades.service                    loaded active running Unattended Upgrades Shutdown
  user@1000.service                              loaded active running User Manager for UID 1000

lines 1-26

5. Conclusion
This document outlines the complete process of creating a security audit and hardening script, from individual command testing to script execution. This approach ensured that each step was thoroughly validated, resulting in a reliable and effective script. The final script, along with this documentation, has been uploaded to the GitHub repository for further use and reference.

