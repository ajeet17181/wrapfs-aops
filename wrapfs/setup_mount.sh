umount /mnt/wrapfs/;
umount /mnt/ext3/;
rmmod wrapfs;
insmod fs/wrapfs/wrapfs.ko;
mount -t ext3 /dev/mapper/VolGroup00-LogVol00 /mnt/ext3;
if [ "$1" ] 
then
mount -t wrapfs -o $1 /mnt/ext3 /mnt/wrapfs;
else 
mount -t wrapfs /mnt/ext3 /mnt/wrapfs;
fi
