docker run -ti -v "$PWD/data:/data" -w "/data" --user $(id -u):$(id -g) \
       volatility python2 /volatility/vol.py -f dump imagecopy -O dump.raw
