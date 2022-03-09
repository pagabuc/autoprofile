qemu-system-x86_64 -enable-kvm -monitor tcp::1114,server,nowait -net user,hostfwd=tcp::6543-:22 -net nic -hda debian-buster.qcow2 -m 2G  -s
