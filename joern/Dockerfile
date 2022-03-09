FROM debian:jessie

RUN apt-get update && apt-get install -y wget build-essential ant graphviz libgraphviz-dev lsof \
                                         python python-pygraphviz python-setuptools python-dev python-pip git curl unzip


# Install Oracle's Java 7
WORKDIR /
COPY jdk-7u80-linux-x64.tar.gz /
RUN tar xfz jdk-7u80-linux-x64.tar.gz
RUN update-alternatives --install "/usr/bin/java"  "java"  "/jdk1.7.0_80/bin/java"  1
RUN update-alternatives --install "/usr/bin/javac" "javac" "/jdk1.7.0_80/bin/javac" 1
RUN update-alternatives --install "/usr/bin/javaws" "javaws" "/jdk1.7.0_80/bin/javaws" 1
ENV JAVA_HOME '/jdk1.7.0_80/'

# Download joern
RUN wget https://github.com/fabsx00/joern/archive/0.3.1.tar.gz
RUN tar xfzv 0.3.1.tar.gz
WORKDIR /joern-0.3.1

# Download joern lib
RUN wget http://mlsec.org/joern/lib/lib.tar.gz
RUN tar xfz lib.tar.gz

# Download python-joern
RUN wget https://github.com/fabsx00/python-joern/archive/0.3.1.tar.gz -O python-joern.tar.gz
RUN tar xfz python-joern.tar.gz

# Download joern-tools
RUN wget https://github.com/fabsx00/joern-tools/archive/0.3.1.tar.gz -O joern-tools.tar.gz
RUN tar xfz joern-tools.tar.gz

# Install python-joern
WORKDIR /joern-0.3.1/python-joern-0.3.1
RUN git clone https://github.com/technige/py2neo/ && cd py2neo && git checkout fc3299d06065bceccde0daf7de04473d8b319abb && python setup.py install
RUN python setup.py install

# Install joern-tools
WORKDIR /joern-0.3.1/joern-tools-0.3.1
RUN python2 setup.py install

# Build joern
WORKDIR /joern-0.3.1
RUN ant
RUN ant tools

# Setup neo4j
WORKDIR /
RUN curl -L https://neo4j.com/artifact.php?name=neo4j-community-2.1.5-unix.tar.gz > neo4j-community-2.1.5-unix.tar.gz
RUN tar xf neo4j-community-2.1.5-unix.tar.gz && mv neo4j-community-2.1.5 neo4j-community

RUN sed -i 's/org.neo4j.server.database.location=data\/graph.db/org.neo4j.server.database.location=\/kernel\/.joernIndex/' \
    neo4j-community/conf/neo4j-server.properties

RUN wget http://mlsec.org/joern/lib/neo4j-gremlin-plugin-2.1-SNAPSHOT-server-plugin.zip && \
    unzip neo4j-gremlin-plugin-2.1-SNAPSHOT-server-plugin.zip -d /neo4j-community/plugins/gremlin-plugin

# Add scripts
COPY create_index.sh /
COPY list_funcs.sh /
