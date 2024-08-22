#!/bin/bash

# Security Audit and Hardening Script

# Load custom checks from config file if available
CONFIG_FILE="custom_security_checks.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# 1. List all users and groups
echo "Listing all users and groups..."
getent passwd
getent group

# Check for users with UID 0 (root privileges)
echo "Checking for users with UID 0 (root privileges)..."
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Check for users without passwords or with weak passwords
echo "Checking for users without passwords or with weak passwords..."
awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow

# 2. Scan for files and directories with world-writable permissions
echo "Scanning for world-writable files and directories..."
find / -xdev -type d -perm -0002 -print 2>/dev/null
find / -xdev -type f -perm -0002 -print 2>/dev/null

# Check for .ssh directories and secure permissions
echo "Checking .ssh directories for secure permissions..."
find /home -name ".ssh" -exec chmod 700 {} \; -exec chown $USER:$USER {} \;

# Report files with SUID/SGID bits set
echo "Reporting files with SUID/SGID bits set..."
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \;

# 3. List all running services
echo "Listing all running services..."
systemctl list-units --type=service --state=running

# Check for unnecessary or unauthorized services
echo "Checking for unnecessary or unauthorized services..."
UNAUTHORIZED_SERVICES=("example1" "example2")
for service in "${UNAUTHORIZED_SERVICES[@]}"; do
    systemctl is-active --quiet $service && echo "$service is running"
done

# Ensure critical services are running and properly configured
echo "Ensuring critical services are running and configured..."
CRITICAL_SERVICES=("sshd" "iptables")
for service in "${CRITICAL_SERVICES[@]}"; do
    systemctl is-active --quiet $service || echo "$service is not running"
done

# Check for services listening on non-standard or insecure ports
echo "Checking for services listening on non-standard or insecure ports..."
netstat -tuln | grep -Ev "(:22|:80|:443)" # Adjust ports as necessary

# 4. Verify firewall status and configuration
echo "Verifying firewall status and configuration..."
iptables -L
ufw status verbose

# Report open ports and associated services
echo "Reporting open ports and associated services..."
netstat -tuln

# Check for IP forwarding or other insecure network configurations
echo "Checking for IP forwarding and other insecure network configurations..."
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding

# 5. IP and network configuration checks
echo "Performing IP and network configuration checks..."
ip a

# Identify public vs private IPs
echo "Identifying public vs private IPs..."
for ip in $(hostname -I); do
    if [[ "$ip" =~ ^10\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. || "$ip" =~ ^192\.168\. ]]; then
        echo "$ip is private"
    else
        echo "$ip is public"
    fi
done

# 6. Check for available security updates or patches
echo "Checking for available security updates..."
apt-get update -y && apt-get upgrade -y

# Ensure the server is configured for regular updates
echo "Configuring automatic security updates..."
dpkg-reconfigure -plow unattended-upgrades

# 7. Log monitoring
echo "Monitoring logs for suspicious activity..."
grep "Failed password" /var/log/auth.log

# 8. Server hardening steps

# SSH configuration
echo "Implementing SSH key-based authentication..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Disable IPv6 if not required
echo "Disabling IPv6 if not required..."
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Securing the bootloader
echo "Securing the bootloader..."
echo "GRUB_PASSWORD=\$(echo -e \"password\" | grub-mkpasswd-pbkdf2)" >> /etc/default/grub
echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
echo "password_pbkdf2 root \$GRUB_PASSWORD" >> /etc/grub.d/40_custom
update-grub

# Firewall configuration
echo "Implementing recommended iptables rules..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# 9. Custom security checks
if [ -n "$CUSTOM_SECURITY_CHECKS" ]; then
    echo "Running custom security checks..."
    eval "$CUSTOM_SECURITY_CHECKS"
fi

# 10. Reporting and alerting
REPORT_FILE="security_audit_report.txt"
echo "Generating report..."
{
    echo "Security Audit and Hardening Report"
    echo "=================================="
    echo ""
    echo "Date: $(date)"
    echo ""
    echo "Users and Groups:"
    getent passwd
    getent group
    echo ""
    echo "Files and Directories with World-Writable Permissions:"
    find / -xdev -type d -perm -0002 -print 2>/dev/null
    find / -xdev -type f -perm -0002 -print 2>/dev/null
    echo ""
    echo "Running Services:"
    systemctl list-units --type=service --state=running
    echo ""
    echo "Open Ports and Associated Services:"
    netstat -tuln
    echo ""
    echo "Security Updates and Patches:"
    apt-get -s upgrade | grep "upgraded"
    echo ""
    echo "Log Monitoring:"
    grep "Failed password" /var/log/auth.log
} > $REPORT_FILE

echo "Report generated at $REPORT_FILE"

# Optionally, send the report via email if critical issues are found
CRITICAL_ISSUES=$(grep -i "critical" $REPORT_FILE)
if [ -n "$CRITICAL_ISSUES" ]; then
    echo "Sending email alert..."
    mail -s "Critical Security Alert" admin@example.com < $REPORT_FILE
fi

echo "Security audit and hardening process completed."

