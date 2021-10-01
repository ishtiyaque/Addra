#!/bin/bash

sudo apt-get update
sudo apt-get -y install g++
sudo apt-get -y install libssl-dev
sudo apt-get install -y build-essential autoconf libtool pkg-config

pushd ~
wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4.tar.gz
tar -xzvf cmake-3.18.4.tar.gz
pushd cmake-3.18.4
./bootstrap
./bootstrap
make -j4
sudo make install
sudo ln -s /usr/local/bin/cmake /usr/bin/cmake
popd
sudo apt-get -y install clang

git clone https://github.com/microsoft/SEAL.git
pushd SEAL
git checkout 3.5.6
git pull
cmake . -DBUILD_SHARED_LIBS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
make
sudo make install
popd

git clone https://github.com/rpclib/rpclib.git
pushd rpclib
cmake .
make
sudo make install
popd

popd
