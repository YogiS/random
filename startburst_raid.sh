#!/bin/bash

# Function to handle errors
handle_error() {
    local error_message="$1"
    echo "Error: $error_message" >&2
    exit 1
}

# Install mdadm package
yum install -y mdadm || handle_error "Failed to install mdadm package"

# Set fs.aio-max-nr and save it to /etc/sysctl.conf
sysctl -w fs.aio-max-nr=8388608 >> /etc/sysctl.conf || handle_error "Failed to set fs.aio-max-nr"

# Find devices with Amazon EC2 NVMe Instance Storage
devices=""
for device in $(ls /sys/block/); do
    if grep -q -e "Amazon EC2 NVMe Instance Storage" -e "ec2-nvme-instance" /sys/block/${device}/device/subsysnqn 2> /dev/null; then
        devices="${devices} /dev/${device}"
    fi
done

# Output devices to a temporary file
echo "${devices}" > /tmp/devices || handle_error "Failed to output devices to /tmp/devices"

# Create RAID 0 using mdadm
mdadm --create /dev/md0 $(cat /tmp/devices) --level=0 --force --raid-devices=$(cat /tmp/devices | wc -w) || handle_error "Failed to create RAID 0"

# Format /dev/md0 with ext4 without journaling
mkfs.ext4 /dev/md0 -O ^has_journal || handle_error "Failed to format /dev/md0 with ext4"

# Create directory for mounting
mkdir -p /opt/data || handle_error "Failed to create directory /opt/data"

# Mount /dev/md0 to /opt/data
mount /dev/md0 /opt/data || handle_error "Failed to mount /dev/md0 to /opt/data"

# Set ownership for /opt/data
chmod 750 -R /opt/data || handle_error "Failed to set permissions for /opt/data"

# Set permissions for /opt/data
chmod 750 -R /opt/data || handle_error "Failed to set permissions for /opt/data"

echo "Starburst RAID Setup completed successfully"
