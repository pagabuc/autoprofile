FROM debian:buster

RUN apt-get update && apt-get install -y git python3 python3-pip
RUN pip3 install pyelftools avatar2 pebble

ADD angr-dev.tar.gz /
RUN echo "I know this is a bad idea." | angr-dev/setup.sh -i

RUN pip3 install git+https://git@github.com/pagabuc/kallsyms-extractor.git
ADD . /autoprofile/
