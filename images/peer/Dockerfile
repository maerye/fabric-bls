# Copyright Greg Haskins All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0
#
FROM hyperledger/fabric-baseos:amd64-0.4.13
RUN  sed -i 's/http:\/\/cn\./http:\/\//g' /etc/apt/sources.list \
  && apt-get clean \
  && apt-get update --fix-missing \
  && apt-get install -y libgmp-dev build-essential flex bison \
  && wget -O pbc.tar.gz "https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz" \
  && mkdir -p /usr/src/pbc \
  && tar -xzf pbc.tar.gz -C /usr/src/pbc --strip-components=1 \
  && cd /usr/src/pbc \
  && chmod +x ./configure \
  && ./configure \
  && make \
  && make install \
  && ldconfig
