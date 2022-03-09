ROOT="$( cd "$(dirname "$0")" ; pwd -P )"

if [[ $# -ne 2 ]]; then
    echo "USAGE:" `basename $0` "kernel_sources" "profile_name";
    exit -1;
fi;

KDIR=$PWD/$1
NAME=$2

docker run -ti -v "$ROOT/volatility:/volatility" -v "$KDIR:/kernel" --user $(id -u):$(id -g) volatility /bin/bash -c \
       "cd /volatility/tools/linux; \
        make KDIR=/kernel clean; \
        make KDIR=/kernel; \
        mv profile.zip /volatility/volatility/plugins/overlays/linux/$NAME.zip"
