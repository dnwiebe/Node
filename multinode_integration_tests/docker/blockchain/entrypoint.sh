#!/bin/sh

node /app/ganache-core.docker.cli.js \
    -h 0.0.0.0 \
    -p 18545 \
    --networkId 2 \
    --verbose \
    --mnemonic "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term toddler sphere ripple idle dragon curious hold"
