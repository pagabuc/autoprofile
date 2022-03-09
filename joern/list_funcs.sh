sleep 5;
/neo4j-community/bin/neo4j start
sleep 5;
joern-list-funcs > joern.log
echo "Joern found" `wc -l joern.log | cut -f 1 -d " "` "functions"
