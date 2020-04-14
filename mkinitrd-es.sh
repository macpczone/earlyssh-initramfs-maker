#!/bin/bash

set -e

# These defaults should rarely change between machines so they're coded here instead of
# taking values from the kernel command line. You might wish to use a nonstandard SSH port, tho'.
# We use "root" for the root mapper to be consistent with genkernel's implementation that
# unlocks the root into /dev/mapper/root, but really it's arbitrary and could be anything
NET_NIC="eth0"
SSH_PORT="22"
MAPPER="root"

# Add dynamic lib'ed binaries we require for the initramfs. Here we include btrfs as an example
# though this script's generated init doesn't run btrfs device scan
BINS="/sbin/cryptsetup /sbin/mdadm /usr/sbin/dropbear /sbin/lvm"

# The initramfs root directory
RD=$(mktemp -d)

# Prepare basic structure and copy basic files and bins
# This assumes dropbear and busybox are built static
mkdir -p ${RD}/{bin,sbin,dev,etc/dropbear,lib64,mnt/root,proc,root/.ssh,sys,usr/sbin,var/log,var/run}
cp -a /sbin/busybox ${RD}/bin/busybox
cp -a /etc/localtime ${RD}/etc/

# Add lvm symlinks if appropriate
# Also copy the lvm.conf file
if  [ -x /sbin/lvm ] ; then
  ln -s lvm ${RD}/sbin/lvchange
  ln -s lvm ${RD}/sbin/lvrename
  ln -s lvm ${RD}/sbin/lvextend
  ln -s lvm ${RD}/sbin/lvcreate
  ln -s lvm ${RD}/sbin/lvdisplay
  ln -s lvm ${RD}/sbin/lvscan

  ln -s lvm ${RD}/sbin/pvchange
  ln -s lvm ${RD}/sbin/pvck
  ln -s lvm ${RD}/sbin/pvcreate
  ln -s lvm ${RD}/sbin/pvdisplay
  ln -s lvm ${RD}/sbin/pvscan

  ln -s lvm ${RD}/sbin/vgchange
  ln -s lvm ${RD}/sbin/vgcreate
  ln -s lvm ${RD}/sbin/vgscan
  ln -s lvm ${RD}/sbin/vgrename
  ln -s lvm ${RD}/sbin/vgck
  # Conf file(s)
  cp -av /etc/lvm ${RD}/etc
fi

# Copy the authorized keys for your regular user you administrate with (here root for example)
cp /root/.ssh/authorized_keys ${RD}/root/.ssh/

# Copy OpenSSH's host keys to keep both initramfs' and regular ssh signed the same
# otherwise openssh clients will see different host keys and chicken out. Here we only copy the
# ecdsa host key, because ecdsa is default with OpenSSH. For RSA and others, copy adequate keyfile.
dropbearconvert openssh dropbear /etc/ssh/ssh_host_rsa_key ${RD}/etc/dropbear/dropbear_rsa_host_key

# These two libs are needed for dropbear, even if it's built statically, because we don't use PAM
# and dropbear uses libnss to find user to authenticate against
cp -L /lib64/libnss_compat.so.2 ${RD}/lib64/
cp -L /lib64/libnss_files.so.2 ${RD}/lib64/

# Basic system defaults
echo "root:x:0:0:root:/root:/bin/sh" > ${RD}/etc/passwd
echo "root:*:::::::" > ${RD}/etc/shadow
echo "root:x:0:root" > ${RD}/etc/group
echo "/bin/sh" > ${RD}/etc/shells
chmod 640 ${RD}/etc/shadow

cat << EOF > ${RD}/etc/nsswitch.conf
passwd:	files
shadow:	files
group:	files
EOF

# For each of the non-static binary listed above, copy the required libs
# Note: lddtree belongs to app-misc/pax-utils the newer versions of which
# can automatically copy the whole lib tree with --copy-to-tree option
for B in $BINS; do
    cp -f ${B} ${RD}${B}
    lddtree --copy-to-tree ${RD} ${B}
done

# The main init script
cat << EOF > ${RD}/init
#!/bin/busybox sh

/bin/busybox mkdir -p /usr/bin /mnt/root
/bin/busybox --install -s
touch /var/log/lastlog

mount -t devtmpfs none /dev
mount -t proc proc /proc
mount -t sysfs none /sys
/bin/busybox mkdir /dev/pts /dev/shm
/bin/busybox mount -t devpts none /dev/pts
/bin/busybox mount -t tmpfs none /dev/shm

# Root partition and networking could be different between machines so take those configs from the 
# kernel command line
for x in \$(cat /proc/cmdline); do
	case "\${x}" in
		crypt_root=*)
			CRYPT_ROOT=\${x#*=}
		;;
		dev_root=*)
			DEV_ROOT=\${x#*=}
		;;
		net_ipv4=*)
			NET_IPv4=\${x#*=}
		;;
		net_gw=*)
			NET_GW=\${x#*=}
		;;
	esac
done

# Bootstrap the network
ifconfig ${NET_NIC} \${NET_IPv4}
route add default gw \${NET_GW}

cat > /etc/motd <<- EOT
	Welcome to early-ssh for Centos 6!
	
	Type ./unlock and then enter the password for the encrypted volume

	Please send your comments and bugreports to github.com
	EOT

# Start dropbear sshd
/usr/sbin/dropbear -s -g -p $SSH_PORT -B

sleep 1
clear
echo "Press x to enter LUKS password or wait for the root ssh unlock..."

# Wait for the unlocked root mapper to appear
while [ ! -e /dev/mapper/\${CRYPT_ROOT} ]; do
    read -n 1 -t 1 input
    echo -n "."
    if [ "$input" == "x" ]; then
		echo ""
		sleep 1
		/sbin/cryptsetup luksOpen \${DEV_ROOT} ${MAPPER}
		/sbin/vgchange -ay
		/sbin/vgscan --mknodes
    fi
done

mount -o ro /dev/mapper/${MAPPER} /mnt/root

# We kill dropbear or else it will remain in memory and OpenSSH won't be able to bind to the same port!
killall dropbear
ifconfig ${NET_NIC} 0.0.0.0
ifconfig ${NET_NIC} down

for i in \$(export -p); do
    i=\${i#declare -x}
    i=\${i#export}
    i=\${i%%=*}
    [ "\$i" = "root" -o "\$i" = "PATH" -o "\$i" = "HOME" -o "\$i" = "TERM" ] || unset $i
done

umount /dev/pts
umount /dev/shm

echo "Switching the root"
sleep 1
#/bin/busybox sh

mount -n --move /proc /mnt/root/proc
mount -n --move /sys /mnt/root/sys
mount -n --move /dev /mnt/root/dev
cd /mnt/root
# Off we go!
exec switch_root -c /dev/console /mnt/root /sbin/init auto
echo "We have crashed out, I wonder why?"
/bin/busybox sh
EOF

# A very simplistic unlocking helper script that takes a passphrase
# This could be adjusted to take keys for better security
cat << EOF > ${RD}/root/unlock
#!/bin/sh
if [ -z "\$1" ]; then
	echo "Invalid passphrase"
	exit 1
fi
for x in \$(cat /proc/cmdline); do
	case "\${x}" in 
		crypt_root=*)
			CRYPT_ROOT=\${x#*=}
		;;
	esac
done
/sbin/cryptsetup luksOpen \${CRYPT_ROOT} ${MAPPER}
EOF

chmod +x ${RD}/init
chmod +x ${RD}/root/unlock

# Get kernel version from current src Makefile (stolen from genkernel and modified)
#KERN_VER=`grep ^VERSION\ \= /usr/src/linux/Makefile | awk '{ print $3 };'`
#KERN_PAT=`grep ^PATCHLEVEL\ \= /usr/src/linux/Makefile | awk '{ print $3 };'`
#KERN_SUB=`grep ^SUBLEVEL\ \= /usr/src/linux/Makefile | awk '{ print $3 };'`
#KERN_EXV=`grep ^EXTRAVERSION\ \= /usr/src/linux/Makefile | sed -e "s/EXTRAVERSION =//" -e "s/ //g"`
#RD_FILE="initramfs-${KERN_VER}.${KERN_PAT}.${KERN_SUB}${KERN_EXV}.img"
KERN_VER=`uname -r`
RD_FILE="initramfs-earlyssh-${KERN_VER}.img"

# Finally build the initramfs cpio from our RD root, and remove the dir
pushd ${RD} > /dev/null
find . -print0 | cpio --null -ov --format=newc | gzip -9 > /boot/${RD_FILE}
popd > /dev/null
rm -rf ${RD}
