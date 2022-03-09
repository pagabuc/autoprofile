echo "[+] Downloading llvm, clang and compiler-rt..."
wget http://llvm.org/releases/9.0.0/llvm-9.0.0.src.tar.xz; tar xf llvm-9.0.0.src.tar.xz
(cd llvm-9.0.0.src &&

     (cd tools && wget http://llvm.org/releases/9.0.0/cfe-9.0.0.src.tar.xz &&
          tar xf cfe-9.0.0.src.tar.xz && mv cfe-9.0.0.src clang) &&

     (cd tools/clang/tools && wget http://releases.llvm.org/9.0.0/clang-tools-extra-9.0.0.src.tar.xz &&
          tar xf clang-tools-extra-9.0.0.src.tar.xz && mv clang-tools-extra-9.0.0.src extra)

)

cp -r pp-trace/* llvm-9.0.0.src/tools/clang/tools/extra/pp-trace/

echo "[~] Building..."
mkdir llvm-build;
(cd llvm-build &&
     CC=gcc-8 CXX=g++-8 cmake -G "Ninja" -DCMAKE_BUILD_TYPE="Release"  \
       -DLLVM_TARGETS_TO_BUILD=X86        \
       -DLLVM_INCLUDE_DOCS=OFF            \
       -DLLVM_ENABLE_SPHINX=OFF           \
       -DLLVM_PARALLEL_LINK_JOBS=2        \
       -DLLVM_ENABLE_ASSERTIONS=ON        \
       -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
       ../llvm-9.0.0.src
     ninja;
)
