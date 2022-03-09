PROJECT_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"
export CC="gcc" # Or if possibile clang..

# Cleaning
rm -rf ./log compile_commands.json
make mrproper;

# Replacing READ_ONCE macro
sed -i 's/#define READ_ONCE(x) __READ_ONCE(x, 1)/#define READ_ONCE(x) x/' include/linux/compiler.h

# For some unspecified reasons, linux-rpi does not build otherwise.
sed -i 's/compat_ulong_t/u32/' include/linux/broadcom/vc_mem.h
sed -i 's/compat_ulong_t/u32/' drivers/char/broadcom/vc_mem.c

echo "[+] Building the kernel (allyes)..."

make allyesconfig;

# Here we try to remove as many DEBUG options as possible
for i in `cat .config | grep "CONFIG_.*DEBUG.*=y"`; do
    config=`echo $i | cut -f1 -d "="`;
    echo $config
    ./scripts/config --set-val $config n
done

./scripts/config --set-val CONFIG_BROADCOM_PHY n
./scripts/config --set-val CONFIG_NET_VENDOR_BROADCOM n
./scripts/config --set-val CONFIG_WLAN_VENDOR_BROADCOM n

./scripts/config --set-val CONFIG_LOCKDEP n
./scripts/config --set-val CONFIG_PROVE_LOCKING n
./scripts/config --set-val CONFIG_LOCK_STAT n
./scripts/config --set-val CONFIG_COMPILE_TEST n
./scripts/config --set-val CONFIG_DEBUG_KERNEL y
./scripts/config --set-val CONFIG_DEBUG_INFO y

make olddefconfig;

time bear make -j$(nproc) &> log

time python3 $PROJECT_ROOT/run_clang.py
