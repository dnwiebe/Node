# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

FROM trufflesuite/ganache-cli:v6.12.2

ADD ./amd64_linux/entrypoint.sh /app/

EXPOSE 18545

ENTRYPOINT /app/entrypoint.sh