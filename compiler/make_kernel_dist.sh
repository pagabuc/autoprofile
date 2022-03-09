export CC="gcc"

rm -rf *.deb log

make clean -j4 &> /dev/null;

echo "[+] Building the kernel (dist)..."

if grep -q "HAVE_ARCH_PREL32_RELOCATIONS" ./arch/x86/Kconfig; then
    sed -i "/HAVE_ARCH_PREL32_RELOCATIONS/d" ./arch/x86/Kconfig;
    ./scripts/config --set-val CONFIG_HAVE_ARCH_PREL32_RELOCATIONS n
fi

./scripts/config --set-val CONFIG_DEBUG_KERNEL y
./scripts/config --set-val CONFIG_DEBUG_INFO y
./scripts/config --set-val CONFIG_KALLSYMS_ALL y
./scripts/config --set-val CONFIG_RANDOMIZE_BASE n


make olddefconfig;
make -j$(nproc) deb-pkg &> log
mv ../linux-*.deb .
