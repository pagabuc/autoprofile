docker run -ti --rm -v "/tmp/:/tmp/" -v "$PWD:$PWD" -w "$PWD" autoprofile python3 /autoprofile/core.py .
