#!/bin/bash

# Function to display the top 10 CPU and Memory-consuming processes
display_cpu_mem() {
    echo "Top 10 CPU and Memory consuming processes:"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 11
    echo ""
}

# Function to display network statistics
display_network() {
    echo "Network statistics:"
    echo "Number of concurrent connections to the server:"
    ss -s | grep "TCP:" | awk '{print $2}'
    
    echo "Packet drops:"
    ip -s link | awk '/errors:/ {print "Interface:", $0}'
    
    echo "MB in and out:"
    ip -s link | awk '/RX:|TX:/ {getline; print $1, $2}'
    echo ""
}

# Function to display disk space usage
display_disk_space() {
    echo "Disk space usage by mount partition:"
    df -h | awk '$5+0 > 80 {print $0}'
    echo ""
}

# Function to display system load average
display_load_average() {
    echo "Current load average for the system:"
    uptime
    echo "CPU usage breakdown (usr, system, idle, etc):"
    mpstat || top -bn1 | grep "Cpu(s)"
    echo ""
}

# Function to display memory usage
display_memory() {
    echo "Memory usage:"
    free -m
    echo "Swap memory usage:"
    free -m | grep "Swap"
    echo ""
}

# Function to display active processes
display_active_processes() {
    echo "Number of active processes:"
    ps aux | wc -l
    echo "Top 5 processes by CPU and memory usage:"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
    echo ""
}

# Function to monitor essential services
monitor_services() {
    echo "Monitoring essential services (sshd, nginx/apache, iptables):"
    for service in sshd nginx apache2 iptables; do
        if systemctl is-active --quiet $service; then
            echo "$service is running"
        else
            echo "$service is not running"
        fi
    done
    echo ""
}

# Main logic for handling command-line switches
while getopts "cmndlas" option; do
    case $option in
        c) display_cpu_mem ;;
        n) display_network ;;
        d) display_disk_space ;;
        l) display_load_average ;;
        a) display_memory ;;
        s) monitor_services ;;
        *) echo "Invalid option" ;;
    esac
done

# If no option is provided, display the full dashboard
if [ $OPTIND -eq 1 ]; then
    display_cpu_mem
    display_network
    display_disk_space
    display_load_average
    display_memory
    display_active_processes
    monitor_services
fi

