#!/bin/bash

ROOT="$( cd "$(dirname "$0")" ; pwd -P )"
TEMP='/tmp/vol_out';
rm -rf $TEMP; mkdir $TEMP;

VOLATILITY="docker run -v $ROOT/volatility:/volatility -v $PWD/data:/data -v $TEMP:$TEMP --user $(id -u):$(id -g) volatility python2 /volatility/vol.py -f /data/dump"

plugins=("linux_arp"
         "linux_banner"
         "linux_check_afinfo"
         "linux_check_creds"
         "linux_check_fop"
         "linux_check_idt"
         "linux_check_modules"
         "linux_check_syscall"
         "linux_check_tty"
         "linux_cpuinfo"
         "linux_dentry_cache"
         "linux_dmesg"
         "linux_dump_map --dump-dir XXX"
         "linux_dynamic_env"
         "linux_elfs"
         "linux_enumerate_files"
         "linux_find_file -L"
         "linux_getcwd"
         "linux_hidden_modules"
         "linux_ifconfig"
         "linux_info_regs"
         "linux_iomem"
         "linux_keyboard_notifiers"
         "linux_ldrmodules"
         "linux_library_list"
         "linux_librarydump --dump-dir XXX"
         "linux_list_raw"
         "linux_lsmod"
         "linux_lsof"
         "linux_malfind"
         "linux_memmap"
         "linux_moddump --dump-dir XXX"
         "linux_mount"
         "linux_mount_cache"
         "linux_netscan"
         "linux_netstat"
         "linux_pidhashtable"
         "linux_plthook"
         "linux_plthook -a"
         "linux_proc_maps"
         "linux_proc_maps_rb"
         "linux_procdump --dump-dir XXX"
         "linux_psaux"
         "linux_psenv"
         "linux_pslist"
         "linux_pslist_cache"
         "linux_psscan"
         "linux_pstree"
         "linux_psxview"
         "linux_recover_filesystem --dump-dir XXX"
         "linux_sk_buff_cache --dump-dir XXX"
         "linux_slabinfo"
         "linux_threads"
         "linux_tmpfs -L"
         "linux_tmpfs -S 1 -D XXX"
         "linux_truecrypt_passphrase"
         "linux_vma_cache"
        );

check_process_count(){
    # Let's check if there are more than 20 processes.
    pscount=`$VOLATILITY --profile=$PROFILE linux_pslist |& grep "0x" | wc -l`
    if [ "$pscount" -lt 20 ]; then
       echo "Less than 20 process? Check this!!";
       exit;
    fi
}

list_profiles(){
    $VOLATILITY --info 2>&1 | grep "^Linux.*Profile"
}

PROFILE=$1
AVAILABLE_PROFILES=`list_profiles`

if [[ -z $PROFILE ]] || [[ ! $AVAILABLE_PROFILES =~ "$PROFILE " ]]; then
    echo "USAGE:" `basename $0` "[profile]";
    echo "Available profiles:"
    echo "$AVAILABLE_PROFILES"
    exit -1;
fi;

target=`echo $PROFILE | sed -e 's/Linux\(.*\)x64/\1/'`
outdir=$PWD/plugins_output_$target
rm -rf $outdir && mkdir $outdir;
echo "[+] Saving in: $outdir"

check_process_count

ulimit -Sv 10000000;
for PLUGIN in "${plugins[@]}"; do
    echo "Running for $target : $PLUGIN";
    output=$outdir/`echo $PLUGIN | tr " /-" _`
    PLUGIN=${PLUGIN/XXX/`mktemp -d $TEMP/XXXXXX`};
    echo $PLUGIN
    sem -j8 $VOLATILITY --profile=$PROFILE $PLUGIN &> $output.log
done

sem --wait;

field_accessed=$outdir/fields_accessed.txt
echo "Extracting accesses in $field_accessed";
find $outdir -type f  | xargs cat | grep "ACCESS:" | sort -u -S2G --parallel=8 | grep -v "idt_desc\|bash_hash\|gate_struct\|elf64_\|elf32_"  > $field_accessed
