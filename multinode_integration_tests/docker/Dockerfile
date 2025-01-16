# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#FROM debian:stable-slim
#FROM debian:buster-slim
#FROM debian:bullseye-slim
#FROM debian:bookworm-slim
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y libc6 && \
# These lines are commented out because for some reason the installation of iptables-persistent hangs forever on
# bullseye-slim. Its absence means that the NodeStartupConfigBuilder::open_firewall_port() function won't work, but
# at the time of this comment it's used in only one place in a way that doesn't have any value. So we decided to
# comment that out and continue adding value rather than spending time getting this to work for no profit.
#    apt-get install -y debconf-utils && \
#    echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections && \
#    echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections && \
#    apt-get install -y iptables-persistent && \
    apt-get install -y procps
COPY generated/port_exposer /usr/local/bin/port_exposer

ENV SUDO_UID 1000
ENV SUDO_GID 1000
ENV RUST_BACKTRACE full

CMD tail -f /dev/null
