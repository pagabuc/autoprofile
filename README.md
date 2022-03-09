### Introduction
<a href="https://pagabuc.me/docs/tops22_autoprofile.pdf"> <img title="" src="https://pagabuc.me/assets/img/autoprofile.jpg" align="right" width="205"></a>
This repository contains the software developed for the paper "AutoProfile: Towards Automated Profile Generation for Memory Analysis", available [here](https://pagabuc.me/docs/tops22_autoprofile.pdf).

```
@article{pagani2021autoprofile,
  title={AutoProfile: Towards Automated Profile Generation for Memory Analysis},
  author={Pagani, Fabio and Balzarotti, Davide},
  journal={ACM Transactions on Privacy and Security},
  volume={25},
  number={1},
  pages={1--26},
  year={2021},
  publisher={ACM New York, NY}
}
```

### How To

The following steps document how to reproduce the RPI experiment presented in the paper.

#### Setup

```
    git clone https://github.com/pagabuc/autoprofile
    cd autoprofile; export PROJECT=$PWD;

    cd $PROJECT/compiler; docker build -t compiler .
    cd $PROJECT/joern; [download jdk-7u80-linux-x64.tar.gz from https://www.oracle.com/java/technologies/javase/javase7-archive-downloads.html] ; docker build -t joern .
    cd $PROJECT/volatility; tar xvfz volatility.tar.gz; docker build -t volatility .
    cd $PROJECT/src; tar xvfz angr-dev.tar.gz; docker build -t autoprofile .
```

#### Setup a target folder

```
    mkdir -p tests/rpi/data
    git clone --depth=1 --branch rpi-5.6.y https://github.com/raspberrypi/linux tests/rpi/linux
    cp -r tests/rpi/linux tests/rpi/linux-rpi
    cp -r tests/rpi/linux tests/rpi/linux-rpi-allyes
    cp -r tests/rpi/linux tests/rpi/linux-rpi-joern
    rm -rf tests/rpi/linux
```

#### Extract access chains

```
    cd tests/rpi/linux-rpi-allyes/
    bash $PROJECT/compiler/compiler_allyes.sh
```

#### Run Joern

```
    cd tests/rpi/linux-rpi-joern
    bash $PROJECT/joern/joern.sh
```

#### Build the target kernel

```
    cd tests/rpi/linux-rpi/
    make defconfig   # Or put your configuration in .config
    bash $PROJECT/compiler/compiler_dist.sh
```


#### Copy files into the target's data folder
```
    cd $PROJECT/tests/rpi/
    cp linux-rpi/vmlinux data/
    cp linux-rpi/*.deb   data/
    cp linux-rpi-allyes/plugin.json   data/
    cp linux-rpi-allyes/pptrace.json data/
    cp linux-rpi-joern/joern.log data/
```

#### Create a QEMU VM

```
    cd $PROJECT/images/
    wget http://s3.eurecom.fr/~pagabuc/debian-buster.qcow2.tar.gz
    tar xvfz debian-buster.qcow2.tar.gz
```

Or create a VM manually:

```
    cd $PROJECT/images/
    wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-10.9.0-amd64-netinst.iso
    qemu-img create -f qcow2 debian-buster.qcow2 20G
    qemu-system-x86_64 -m 2G -hda debian-buster.qcow2 -cdrom debian-10.9.0-amd64-netinst.iso -boot d
    [follow the installation process and shutdown the vm]
```

#### Install the kernel, acquire a memory dump, and convert it to raw
```
    cd $PROJECT/tests/rpi
    bash $PROJECT/images/install-and-dump.sh
    bash $PROJECT/volatility/convert.sh
```

#### Create Volatility profile and run plugins to collect accessed fields
```
    cd $PROJECT/tests/rpi/
    bash $PROJECT/volatility/make_profile.sh linux-rpi rpi
    bash $PROJECT/volatility/run_plugins.sh Linuxrpix64
    [check that $PROJECT/tests/rpi/data/ contains field_accessed.txt]
```

#### Run AutoProfile (you can follow the status in $PROJECT/tests/rpi/output/log)
```
    cd $PROJECT/tests/rpi/
    bash $PROJECT/autoprofile.sh
```

#### Check extracted fields and copy extracted profile:
```
    cd $PROJECT/tests/rpi/
    docker run -ti --rm -v "/tmp/:/tmp/" -v "$PWD:$PWD" -w "$PWD" autoprofile python3 /autoprofile/fields_results.py
    cp output/profile.zip $PROJECT/volatility/volatility/volatility/plugins/overlays/linux/rpi-ape.zip
```

#### Run plugins with the extracted profile:
```
    cd $PROJECT/tests/rpi/
    bash $PROJECT/volatility/run_plugins.sh Linuxrpi-apex64
```



#### Examples of access chains with explanation

The following chains can be extracted with `grep "\[CHAINS\]" $PROJECT/tests/rpi/log`, after running Autoprofile:

  - `<retval fs/proc/array.c:602:do_task_stat struct mm_struct->start_data | A |  get_task_mm | >[0]`


    This chain represents an access of `mm_struct->start_data` at [fs/proc/array.c:602](https://elixir.bootlin.com/linux/v5.4.71/source/fs/proc/array.c#L602). The base of the chain (in this case the variable `mm` of the function) is initialized by the return value (`retval`) of the function `get_task_mm` (this happens [here](https://elixir.bootlin.com/linux/v5.4.71/source/fs/proc/array.c#L453))


  - `<param security/selinux/hooks.c:3758:selinux_file_mprotect struct vm_area_struct->vm_mm|struct mm_struct->start_stack | A-A |  0 | >[0]`


    This chain represents the access happening [here](https://elixir.bootlin.com/linux/v5.4.71/source/security/selinux/hooks.c#L3739) and in this case we have two objects chained together. The base (variable `vma`) is initialized from the first parameter (position 0) of the `selinux_file_mprotect` function.
