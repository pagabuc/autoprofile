docker run --rm -v "$PWD:/kernel" -w "/kernel" joern bash /create_index.sh
sleep 5;
docker run --rm -v "$PWD:/kernel" -w "/kernel" joern bash /list_funcs.sh
