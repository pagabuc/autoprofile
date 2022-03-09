FROM debian:buster

RUN apt-get update && apt-get install -y python2 wget build-essential python2-dev dwarfdump zip yara python-yara
RUN wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
RUN python2 get-pip.py
RUN pip2 install distorm3 pycrypto
COPY volatility/ /volatility
