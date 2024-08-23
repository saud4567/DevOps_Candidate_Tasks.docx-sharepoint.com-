
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
use all this command for a particular proxy server
After run the script output i got 

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








 
