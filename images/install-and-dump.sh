IMAGES="$( cd "$(dirname "$0")" ; pwd -P )"

if ! command -v sshpass &> /dev/null
then
    echo "[-] sshpass not be found, please install it: $ apt-get install sshpass"
    exit
fi

# convert_raw() {
#     python2.7 ~/Research/profiless/volatility/vol.py -f $1 imagecopy -O $2
# }

take_qemu_dump() {
    echo "stop" | nc localhost 1114 -q0
    while true; do
        rip="0x"$(echo "info registers" | nc localhost 1114  -q10 | grep "RIP" | cut -f 1 -d " " | cut -f 2 -d "=")
        echo "RIP: -- "$rip" --";
        res=`python -c "print($rip >= 0xffffffff00000000)"`
        if [[ $res == "True" ]]; then
            break
        fi;
        echo "cont" | nc localhost 1114 -q0
        sleep 1;
        echo "stop" | nc localhost 1114 -q0
    done;
    echo "dump-guest-memory -p `realpath $1` " | nc localhost 1114 -q30
    echo "cont" | nc localhost 1114 -q0;
}

run_ssh_cmd(){
    sshpass -p root ssh root@localhost -p 6543 $*
}

cp $IMAGES/debian-buster.qcow2 debian-buster.qcow2;
echo 'Running QEMU and waiting 10 seconds..'
bash $IMAGES/run-qemu.sh &
sleep 10;

debs=`ls data/*.deb | grep -v -- -dbg`
if [ -z "$debs" ]; then echo "No debs found.. quitting"; exit; fi;

sshpass -p root scp -P 6543 $debs root@localhost:/root/

run_ssh_cmd DEBIAN_FRONTEND=noninteractive apt-get remove -y linux-image-'`uname -r`' linux-image-amd64

echo 'Installing new kernel...'
run_ssh_cmd dpkg -i /root/linux-image*.deb
echo -e "\n -- Kernel Installed, rebooting -- \n"

run_ssh_cmd 'echo "allow-hotplug enp0s3" >> /etc/network/interfaces'
run_ssh_cmd 'echo "iface enp0s3 inet dhcp" >> /etc/network/interfaces'
run_ssh_cmd reboot
sleep 20;

echo 'We are now running kernel:'
run_ssh_cmd 'uname -a'

echo '-- Inserting some kernel modules'
run_ssh_cmd 'find / -name "*.ko" -exec insmod {} \; &> /dev/null'
run_ssh_cmd 'lsmod'

run_ssh_cmd "sleep 100" &
take_qemu_dump ./data/dump
run_ssh_cmd poweroff &
