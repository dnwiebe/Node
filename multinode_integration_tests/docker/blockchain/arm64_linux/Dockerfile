# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

# This is version v6.12.2 according to the official ganache versioning
FROM --platform=linux/arm64 nutrina/ganache-cli:0.3

ADD ./arm64_linux/entrypoint.sh /app/

EXPOSE 18545

ENTRYPOINT /app/entrypoint.sh