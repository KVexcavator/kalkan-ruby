#!/bin/bash

if [ "$1" == "1.1.0" ]; then
    export PATH=/usr/local/openssl-1.1.0/bin:$PATH
    export LD_LIBRARY_PATH=/usr/local/openssl-1.1.0/lib:$LD_LIBRARY_PATH
    echo "Switched to OpenSSL 1.1.0"
elif [ "$1" == "default" ]; then
    export PATH=$(echo $PATH | sed -e 's#/usr/local/openssl-1.1.0/bin:##')
    export LD_LIBRARY_PATH=$(echo $LD_LIBRARY_PATH | sed -e 's#/usr/local/openssl-1.1.0/lib:##')
    echo "Switched to default OpenSSL"
else
    echo "Usage: source switch_openssl.sh [1.1.0|default]"
fi
