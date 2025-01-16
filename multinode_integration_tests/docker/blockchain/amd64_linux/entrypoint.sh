#!/bin/sh

# All wallets begin with null balances. The only exception is the contract owner wallet whose means are to be
# redistributed from there to every account that would need it. (Notice the argument --account '<contract owner wallet
# private key>,<ETH in wei>' that assigns a certain initial balance.) This same principle of initialization needs to be
# regarded, during the test setup, and applied with both the transaction fee (wei of ETH) and the service fee (MASQ).
# While on the transaction fee it's a choice done by us, with the latter, there probably isn't any other solution given
# the mechanism how the deployment of the blockchain smart contract generates the entire token supply only on
# the account of the contract owner's wallet from where it must be sent out to other wallets if needed.

node /app/ganache-core.docker.cli.js \
  -p 18545 \
  --networkId 2 \
  --verbose \
  --mnemonic "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term toddler sphere ripple idle dragon curious hold"