#!/bin/bash -evx
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

arch=`dpkg --print-architecture`

if [[ $arch == "amd64" ]]; then

    echo "Building ganache-cli image for linux/amd64 architecture"
    docker build -t ganache-cli . -f amd64_linux/Dockerfile

elif [[ $arch == "arm64" ]]; then

    echo "Building ganache-cli image for linux/arm64 architecture"
    docker build -t ganache-cli . -f arm64_linux/Dockerfile

fi

