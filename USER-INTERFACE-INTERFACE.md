# Communication Between `MASQNode` and User Interfaces

## Background

### Project Architecture

The `MASQNode` (or `MASQNode.exe` for Windows) binary is used for two different purposes. One is called the Daemon;
the other is called the Node.

The Node contains all the communications capabilities MASQ is known for. Its job is to start with root privilege,
open low ports, drop privilege to user level, and settle into sending and receiving CORES packages.

The Daemon is different. Its job is to start when the machine boots, with root privilege, and keep running with
root privilege until the machine shuts down. It is not allowed to communicate over the Internet, or with the Node.
This reduces the chance that an attacker's hack of the Node could gain root privilege on a user's machine.

Since the Daemon is always running, it listens on a `localhost`-only port (5333 by default) for connections
from user interfaces. UIs connect first to the Daemon on its well-known port. There are certain conversations that
the Daemon can carry on with the UI (one of which tells the Daemon to start up the Node), but when it's time, the
Daemon will tell the UI where the Node is so that the UI can connect directly to the Node.

If the Node crashes, the UI should reconnect to the Daemon. From there, if desired, it can direct the Daemon to
restart the Node.

Any number of UIs can connect to the Daemon and the Node. Information that is relevant only to one UI is sent only
to that UI; information that is relevant to all is broadcast. Currently there is no way for a UI to subscribe
only to those broadcasts in which it is interested; it will receive all broadcasts and has the responsibility to
ignore those it doesn't care about. If necessary, the subscription functionality can be added to the Node in the
future.

### Communications Architecture

#### Level 1

If the Daemon is started without specific settings, like this

```
$ ./MASQNode --initialization
```

it will try to come up listening for UI connections on port 5333. But if it's started like this

```
$ ./MASQNode --initialization --ui-port 12345
```

it will try to come up listening for UI connections on port 12345. If it finds the target port already occupied, it
will fail to start.

The Node is started by the Daemon. When the Daemon starts the Node, it will choose an unused port and direct the
Node to listen for UIs on that port. When the Daemon redirects a UI to the Node, it will supply in the redirect
message the port on which the Node is running.

The Daemon and the Node listen for UIs only on the `localhost` pseudo-NIC. This means that all the UIs for a particular
Daemon or Node must run on the same computer as the Daemon or Node: they cannot call in over the network from another
machine. This restriction is in place for security reasons.

#### Level 2

The link between the UIs and the Daemon or Node is insecure WebSockets, using the protocol name of `MASQNode-UIv2`.
Any other protocol name will be rejected, and no connection will be made.

#### Level 3

Once the WebSockets connection is established, all the messages passed back and forth between the UIs and the Daemon
or Node are formatted in JSON. A message packet is always a JSON object, never a scalar or an array.

#### Level 4

The low-level JSON format of `MASQNode-UIv2` messages is reasonably simple. It looks like this:

```
{
    "opcode": <string>,
    "contextId": <positive integer>,
    "payload": <optional object>,
    "error": <optional object>
}
```

The `opcode` is a short string that identifies the message type. If a message is a request (UI to Node) and the
protocol dictates that a response (Node to UI) should result from it, both the request and the response will have
the same opcode.

The `contextId` is a positive integer best thought of as a conversation number. Just as there can be many UIs 
connected to the same Node, each UI can be carrying on many simultaneous conversations with the Node. When a 
request is sent as part of a unique conversation, the Daemon and the Node guarantee that the next message 
received in that conversation will be the response to that request. It is the responsibility of each UI to 
manage `contextId`s. When the UI wants to start a new conversation, it merely mentions a new `contextId` in 
the first message of that conversation; when it's done with a conversation, it just stops mentioning that 
conversation's `contextId`.

It may be tempting to use a single `contextId` for all the messages a UI sends in its lifetime, and this is
perfectly legal as far as the Node and Daemon are concerned; but if the UI does this, it will have to determine
for itself which conversation each incoming message is part of. For example, if there are three conversations
going on at once, this might happen:

1. → Request for conversation 1
1. → Request for conversation 2
1. ← Response for conversation 1
1. → Request for conversation 3
1. ← Broadcast from Node
1. ← Response for conversation 3
1. ← Response for conversation 2

If each conversation has its own ID, it'll be a lot easier to tell what's going on when a message arrives
than it will be if every message is part of conversation 555.

At the other extreme, a UI may choose to start a new conversation for every request/response pair. This is fine.

Some messages are always isolated, and never part of any conversation, like the Broadcast in step 5 above. 
These messages will be identifiable by their `opcode`, and their `contextId` should be ignored. (In the 
real world, it's always zero, but depending on that might be dangerous.)

Neither the Daemon nor the Node will ever start a conversation, although they will send isolated, non-conversational
messages.

The `payload` is the body of the message, with its structure being signaled by the contents of the `opcode` field.
See the Message Reference section below for specifics about the `payload` field for each type of message.
It will be present if and only if the `error` field is not present.

The object in the `error` field, if present, tells about the error that was encountered in the process of trying to
satisfy a request. It will be present if and only if the `payload` field is not present. It will have this structure:

```
{
    code: <nonnegative integer>,
    message: <string>
}
```

The `code` field is a 64-bit integer. Its numeric value is not particularly important, but it denotes a kind of
error. The UI can tell whether a particular operation is producing the same kind of error repeatedly, or different
kinds of errors, by comparing one `code` to the next.

The `message` field is a string with a hopefully-friendly description of the error.

There is no provision in the `MASQNode-UIv2` protocol for UIs to communicate with one another. A UI may be able
to deduce, from broadcasts, the existence of other UIs, but it can never be assured that there _aren't_ any other UIs
connected to the Node or Daemon.

#### Level 5

The structure of the `payload` of a `MASQNode-UIv2` message depends on the `opcode` of that message. See the
Message Reference section below.

## General Operational Concepts

### Daemon

#### Setup

The Node requires quite a bit of configuration information before it can start up properly. There are several
possible sources of this configuration information. The primary source, though, is the command line that's used
to start the Node. There are many parameters that can be specified on that command line, and the Daemon needs to
know them all in order to start the Node.

Accumulating this information is the purpose of the Daemon's Setup functionality, which is a large proportion of
what it does.

The Daemon has a space inside it to hold Setup information for the Node. A UI can query the Daemon to get a dump
of the information in the Setup space. When the Node is not running, the information in the Setup space can be
changed by the UI. When the Node is running, the information in the Setup space is frozen and immutable. This is
so that when the Node is running, you can use the UI to query the Daemon to discover the configuration with which
the Node was started.

If a Node is shut down, a new Node can easily be started with exactly the same configuration as its predecessor
as long as the information in the Setup space is not disturbed.

#### Start

When the Start operation is triggered, the Daemon will try to start the Node with the information in the Setup
space. The response message will tell whether the attempt succeeded or failed. 

#### Redirect

As long as the UI sends the Daemon messages that the Daemon understands, the Daemon will respond appropriately to
them. But if the UI sends the Daemon a message the Daemon doesn't understand, the Redirect operation may come
into play.

If the Node is not running, there's nowhere to Redirect, so the Daemon will just send back an error response.

However, if the Node _is_ running, the Daemon will send back a Redirect response, which will contain both
information about where the Node is running and also the unexpected message sent to the Daemon. When the UI
gets a Redirect, it should drop the WebSockets connection to the Daemon, make a WebSockets connection to the
Node on the port supplied in the Redirect message (on `localhost`, using the `MASQNode-UIv2` protocol), and
resend the original message--which, in case the UI doesn't remember it anymore, is helpfully included in the
Redirect payload.  If it's a valid Node message, the Node should respond appropriately to it.

### Node

#### Database password

The Node stores its configuration information in a database. A UI should certainly never attempt to write to
this database, but it also shouldn't attempt to read from it, for two reasons: first, some of the information
in the database is encrypted because it's sensitive; and second, the Node does some caching work for performance
reasons, so what a UI finds in the database might be several minutes or more old. The UI should ask the Node
directly for the information it needs.

The information in the database that's encrypted needs a password to decrypt it. When the Node is first installed,
there is no secret information in the database; therefore, the database has no password. A password can be set 
on the database without storing any secrets in it, if desired, but in order to store secrets, a password _must_
be set on the database.

The password is never stored anywhere but in memory by the Node; it should not be persisted anywhere by a UI
either. In order to carry out certain instructions, the Node will need the password from the UI, which means the
UI will need to get it from the user.

Using `MASQNode-UIv2` messages, the UI can check to see if a password is correct; it can change the database
password (if it knows the old one); and it can be notified when some other UI changes the password (so that it
knows the one it's aware of is no longer valid).

#### Configuration

The configuration information with which the Node runs (which is different from the setup information with
which the Daemon starts a Node) is available via `MASQNode-UIv2` as well. A UI can request the configuration
information, and if the information changes for some reason, all UIs will be notified so that--if desired--they
can request the latest version.

#### Shutdown

The Shutdown operation causes the Node to cease operations and terminate. The UI will receive a response, and then
the WebSockets connection will be dropped by the Node.

Whenever the WebSockets connection is dropped, whether the Shutdown operation is in progress or not, the UI should
reconnect to the Daemon.

If for some reason the WebSockets connection is _not_ dropped by the Node within a few milliseconds of the response
to the Shutdown message, that indicates that the Node has somehow become hung on the way down. In this case, the
WebSockets connection to the Node will probably be of no further use. The UI may choose to inform the user that
bad things are happening which will probably require user intervention.

## Message Reference

The following messages are listed in alphabetical order by opcode. If several messages have the same opcode,
they'll be ordered under that opcode with the request first and the response later. The `opcode` and `contextId`
fields are not included in the message layouts, but they must be provided by the UI and will be specified
by the Daemon or Node.

The various errors that can result from each request are not specifically mentioned unless they indicate a
condition the UI can correct.

#### `changePassword`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "oldPasswordOpt": <optional string>,
    "newPassword": <string>,
}
```
##### Description:
This message is used to change the database password, provided the UI knows the existing password or is
correctly aware of the fact that there is no existing password.

If the database currently has no password, omit the `oldPasswordOpt` field. If there's already a database
password, there is no way to remove it, even if the database does not yet contain secrets.

#### `changePassword`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
}
```
##### Description:
If the password was successfully changed, this is a simple acknowledgment that the change is complete.

#### `checkPassword`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPasswordOpt": <string>
}
```
##### Description:
This message is used to check whether a password the UI knows is actually the real database
password.

Note that under some circumstances, during the first few minutes after installation, a new MASQNode
may not have any database password at all.

There's no way to make the Node tell you what the database password is, but if you have an idea
what it might be, you can check your idea by sending this message with your idea in the
`dbPasswordOpt` field. If you're checking to see whether there's no password, pass `null` in this
field, or leave it out.

#### `checkPassword`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "matches": <boolean>
}
```
##### Description:
If you send a `checkPassword` request to the Node, it will respond with this message. If the
password you proposed (or the absence-of-password you proposed) matched the database password,
the `matches` field will be `true`; otherwise it will be `false`.

If there was an error checking the password, you'll get a standard error response with a 64-bit
code, where the high-order eight bits are 0x01.

#### `configuration`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPasswordOpt": <optional string>
}
```
##### Description:
This message requests a dump of the Node's current configuration information. If you know the database password,
provide it, and the response will contain the secrets in the database. If you don't supply a password, or you
do but it's wrong, you'll still get a response, but it will have only public information: the secrets will be
missing.

Another reason the secrets might be missing is that there are not yet any secrets in the database.

#### `configuration`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "blockchainServiceUrl": <optional string>,
    "chainName": <String>, 
    "clandestinePort": <string>,
    "currentSchemaVersion": <string>,
    "earningWalletAddressOpt": <optional string>,
    "gasPrice": <number>,
    "neighborhoodMode": <string>,
    "consumingWalletPrivateKeyOpt": <optional string>,
    "consumingWalletAddressOpt": <optional string>,
    "startBlock": <number>,
    "pastNeighbors":[
        <string>,
        <string>, ...
    ],
    "paymentThresholds": {
        "debtThresholdGwei": <number>,
        "maturityThresholdSec": <number>,
        "paymentGracePeriodSec": <number>,
        "permanentDebtAllowedGwei": <number>,
        "thresholdIntervalSec": <number>
        "unbanBelowGwei": <number>
    },
    "ratePack": {
        "routingByteRate": <number>,
        "routingServiceRate": <number>,
        "exitByteRate": <number>,
        "exitServiceRate: <number>"
    },
    "scanIntervals": {
        "pendingPayableSec": <number>,
        "payableSec": <number>,
        "receivableSec": <number>
    },
}
```
##### Description:
This conveys the Node's current configuration information. Some of it is optional: if it's missing, it might be
because it hasn't been configured yet, or it might be because it's secret and you didn't provide the correct
database password. If you want to know whether the password you have is the correct one, try the
`checkPassword` message.

* `blockchainServiceUrl`: The url which will be used for obtaining a communication to chosen services to interact with the 
  blockchain. This parameter is read, if present, only if the same parameter wasn't specified at another place (UI,
  configuration file, environment variables).

* `chainName`: This value reveals the chain which the open database has been created for. It is always present and once 
  initiated, during creation of the database, it never changes. It's basically a read-only value.  

* `clandestinePort`: The port on which the Node is currently listening for connections from other Nodes.

* `consumingWalletPrivateKey`: This is the private key of the consuming wallet, as a 64-digit hexadecimal number.
  It's a secret, so if you don't supply the `dbPasswordOpt` in the request you won't see it.

* `consumingWalletAddress`: This is the address of the consuming wallet, as a 40-digit hexadecimal number prefixed by "0x".

* `currentSchemaVersion`: This will be a version number for the database schema represented as an ordinal numeral. This will
  always be the same for a given version of Node. If you upgrade your Node, and the new Node wants to see a later
  schema version in the database, it will migrate your existing data to the new schema and update its schema
  version. If this attempt fails for some reason, this value can be used to diagnose the issue.

* `earningWalletAddressOpt`: The wallet address for the earning wallet. This is not secret, so
  if you don't get this field, it's because it hasn't been set yet.

* `gasPrice`: The Node will not pay more than this number of gwei for gas to complete a transaction.

* `neighborhoodMode`: The neighborhood mode being currently used, this parameter has nothing to do with descriptors which 
  may have been used in order to set the Node's nearest neighborhood. It is only informative, to know what mode is running
  at the moment. This value is ever present since the creation of the database.    

* `startBlock`: When the Node scans for incoming payments, it can't scan the whole blockchain: that would take
  much too long. So instead, it scans starting from wherever it left off last time. This block number is where
  it left off last time.

* `pastNeighbors`: This is an array containing the Node descriptors of the neighbors the Node is planning to
  try to connect to when it starts up next time.  It's a secret, so if you don't supply the `dbPasswordOpt` in the
  request you won't see it.

* `PaymentThresholds`: These are parameters that define thresholds to determine when and how much to pay other nodes
  for routing and exit services and the expectations the node should have for receiving payments from other nodes for
  routing and exit services. The thresholds are also used to determine whether to offer services to other Nodes or
  enact a ban since they have not paid mature debts. These are ever present values, no matter if the user's set any
  value, as they have defaults.

* `thresholdIntervalSec`: This interval -- in seconds -- begins after maturityThresholdSec for payables and after
  maturityThresholdSec + paymentGracePeriodSec for receivables. During the interval, the amount of a payable that is
  allowed to remain unpaid, or a pending receivable that won’t cause a ban, decreases linearly from the debtThresholdGwei
  to permanentDebtAllowedGwei or unbanBelowGwei.

* `debtThresholdGwei`: Payables higher than this -- in gwei of MASQ -- will be suggested for payment immediately upon
  passing the maturityThresholdSec age. Payables less than this can stay unpaid longer. Receivables higher than this
  will be expected to be settled by other Nodes, but will never cause bans until they pass the maturityThresholdSec +
  paymentGracePeriodSec age. Receivables less than this will survive longer without banning.

* `maturityThresholdSec`: Large payables can get this old -- in seconds -- before the Accountant's scanner suggests
  that it be paid.

* `paymentGracePeriodSec`: A large receivable can get as old as maturityThresholdSec + paymentGracePeriodSec -- in seconds
  -- before the Node that owes it will be banned.

* `permanentDebtAllowedGwei`: Receivables this small and smaller -- in gwei of MASQ -- will not cause bans no matter 
  how old they get.

* `unbanBelowGwei`: When a delinquent Node has been banned due to non-payment, the receivables balance must be paid
  below this level -- in gwei of MASQ -- to cause them to be unbanned. In most cases, you'll want this to be set the
  same as permanentDebtAllowedGwei.

* `ratePack`: These four parameters specify your rates that your Node will use for charging other Nodes for your provided
  services. They are currently denominated in gwei of MASQ, but will be improved to allow denomination in wei units.
  These are ever present values, no matter if the user's set any value, they have defaults.

* `exitByteRate`: This parameter indicates an amount of MASQ demanded to process 1 byte of routed payload while the Node
  acts as the exit Node.

* `exitServiceRate`: This parameter indicates an amount of MASQ demanded to provide services, unpacking and repacking
  1 CORES package, while the Node acts as the exit Node.

* `routingByteRate`: This parameter indicates an amount of MASQ demanded to process 1 byte of routed payload while the
  Node is a common relay Node.

* `routingServiceRate`: This parameter indicates an amount of MASQ demanded to provide services, unpacking and repacking
  1 CORES package, while the Node is a common relay Node.

* `scanIntervals`: These three intervals describe the length of three different scan cycles running automatically in the
  background since the Node has connected to a qualified neighborhood that consists of neighbors enabling a complete
  3-hop route. Each parameter can be set independently, but by default are all the same which currently is most desirable
  for the consistency of service payments to and from your Node. Technically, there doesn't have to be any lower limit 
  for the minimum of time you can set; two scans of the same sort would never run at the same time but the next one is
  always scheduled not earlier than the end of the previous one. These are ever present values, no matter if the user's
  set any value, because defaults are prepared.

* `pendingPayableSec`: Amount of seconds between two sequential cycles of scanning for payments that are marked as currently
  pending; the payments were sent to pay our debts, the payable. The purpose of this process is to confirm the status of
  the pending payment; either the payment transaction was written on blockchain as successful or failed.

* `payableSec`: Amount of seconds between two sequential cycles of scanning aimed to find payable accounts of that meet
  the criteria set by the Payment Thresholds; these accounts are tracked on behalf of our creditors. If they meet the 
  Payment Threshold criteria, our Node will send a debt payment transaction to the creditor in question.

* `receivableSec`: Amount of seconds between two sequential cycles of scanning for payments on the blockchain that have
  been sent by our creditors to us, which are credited against receivables recorded for services provided.

#### `configurationChanged`
##### Direction: Broadcast
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
NOTE: This message is planned, but not yet implemented.

If you receive this broadcast message, then something about the Node's configuration has changed. If you're
interested, you can send a `configuration` request and get the new info; or you can just ignore this message
if you don't care. If you're caching the configuration information, this would be a good time to invalidate
your cache.

#### `connectionStatus`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
This message is used to check the connection status of the node with the MASQ Network.

#### `connectionStatus`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "stage": <string>
}
```
##### Description:
If you send a `connectionStatus` request to the Node, it will respond back with a message containing the stage 
of the connection status with the MASQ Network.

There are following three connection stages:

1. NotConnected: No external neighbor is connected to us.
2. ConnectedToNeighbor: External node(s) are connected to us.
3. RouteFound: You can relay data over the network.

The Node can only be on one of these connection stages during any moment of the Node's lifetime.

#### `crash`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "actor": <string>
    "panicMessage": <string>
}
```
##### Description:
This is a message used only for testing. It will be unrecognized unless the Node that receives it has been
started with the `--crash-point message` parameter. It's used to test the behavior of the Node during a crash
and the reactions of the software around it to that crash.

It makes the Node panic and crash at a specified time that can be chosen by the tester. The normal rule for the
Node is that it's not allowed to crash because of anything it receives over the network from the outside; this
message is an exception to that rule, which is why it must be enabled by a special parameter.

The `actor` field in the payload is the name of the actor (Node subsystem) that will be forced to crash by the
message. As of this writing, the only valid value is "BlockchainBridge".

The `panicMessage` field in the payload is the message that will be passed to the `panic!()` macro by the Node
immediately upon receiving the message.

#### `crash`
##### Direction: Broadcast
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "processId": <integer>,
    "crashReason": {
        <key>: <string>
    }
}
```
##### Description:
When the Node has been running, and the Daemon senses that it is no longer running, the Daemon will broadcast a
`crash` message to all UIs connected to the Daemon. This doesn't necessarily mean the Node has experienced
catastrophic failure: it may have been instructed by a UI to shut down.

The `processId` field contains the platform-dependent process ID of the late Node.

The `crashReason` field is rather clumsy, and there's a card (GH-323) in the backlog to improve it. At the moment,
it's an object with one field, which may be named "ChildWaitFailure", "NoInformation", or "Unrecognized". If the
field is named "ChildWaitFailure" or "Unrecognized", the value is a string with additional information. If the key
is "NoInformation", the value is `null`.

#### `descriptor`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
Requests the Node descriptor from a Node.

#### `descriptor`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "nodeDescriptorOpt": <optional string>
}
```
##### Description:
If the Node has a Node descriptor, it's returned in this message. If the Node has not yet established its Node
descriptor (for example, if it's still waiting on the router to get a public IP address) or will never have a
Node descriptor (for example, if its neighborhood mode is not Standard), the `nodeDescriptorOpt`
field will be null or absent.

#### `financials`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "statsRequired": <boolean>,
    "topRecordsOpt": <optional {
            "count": <positive integer>,
            "orderedBy": <string>
        }>,
    "customQueriesOpt": <optional {
        "payableOpt" : <optional {
            "minAgeS": <positive integer>,
            "maxAgeS": <positive integer>,
            "minBalanceGwei": <positive integer>,
            "maxBalanceGwei": <positive integer>
        }>,
        "receivableOpt": <optional {
            "minAgeS": <positive integer>,
            "maxAgeS": <positive integer>,
            "minBalanceGwei": <positive integer>,
            "maxBalanceGwei": <positive integer>
        }> 
    }>
}
```
##### Description:
This command requests financial statistics from the Node. Without any parameters specified, it produces a brief summary
of financial information; but the output can be customized to show more details.

The details can bear on two different account types stored in two tables of the persistent database. Those types are
payables and receivables.  

One option to get more information about them is a query of the top N records from these financial tables, ordered by
one's preferences, either by balance or age. This command setup always returns two sets of accounts, one set for each
type.

In a different query mode, the user provides a customized query for either payables or receivables or both. The user
will be requested to specify ranges of age and balance to constrain the result set.

The limits for the age range can vary from 0 (as recent as possible) to 9,223,372,036,854,775,807 seconds ago (well
beyond any reasonable scientific estimate of the age of the universe). The limits for the balance range are similarly
generous, except that receivable balances can be negative as well as positive.

It needs to be stated that each mode excludes the other one.

While statistics has been considered the foundation of this command, it reports back structured information about
the Node's historical financial operations. This will include services ordered from other Nodes as well as the opposite,
services provided for other Nodes, represented by monetary values owed and paid to and from this Node's wallets. 

`statsRequired` should be true if historical total balances (see below) are required, false if they are not necessary.
If topRecordsOpt and customQueriesOpt are both null, statsRequired must not be false, since it would produce an empty
response otherwise.

`topRecordsOpt` initiates the request for a given number of top accounts from the tables. An optional feature.
It is important to note that only accounts with positive balances can be displayed by this mode. Some values might stay
out of scope since there might be cases where receivable balances are negative.

`count` is the maximum number of records to be returned. It should be a number between 1 and 65535, inclusive.

`orderedBy` allows you to choose whether the results are sorted in descending order either by `Balance` or `Age`.
It is compulsory to use at least one parameter.

`customQueriesOpt` provides another way to get a subset of accounts, this time by more specific metrics. It works for
both account types, payables and receivables. Possibly only one of them is queried. This query responds well also for 
balances with negative values, and therefore this is a good fit for a complete check of receivable accounts going 
possibly negative. 

`payableOpt` is an optional field with values that configure the customized search for payables. It holds four numbers
that define two ranges of balance and age used as the scope of the search.

`receivableOpt` is an optional field with values that configure the customized search for receivables. It holds four
numbers that define two ranges of balance and age used as the scope of the search.

Both `payableOpt` and `receivableOpt` are complex structures containing four subfields. There is a number in each of
these subfields that represents the end point of the range of either balance or age. Regarding the names of the
subfields, both structures are identical. The only difference lies in the values that the balance parameters can take
on. While receivables are valid between -9223372036854775808 and 9223372036854775807, payables only between 0 and
9223372036854775807.   

`minAgeS` is measured in seconds before the present time and sets a time constraint for the accounts we will be 
searching over; this is the lower limit for the debt's age, or how long it has been since the last payment.

`maxAgeS` is measured in seconds before the present time and sets a constraint for the accounts we will be
searching over; this is the upper limit for the debt's age, or how long it has been since the last payment.

`minBalanceGwei` is represented as an amount of gwei. Any records with balance below this value will not be returned.

`maxBalanceGwei` is represented as an amount of gwei. Any records with balance above this value will not be returned.

#### `financials`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "statsOpt": <optional {  
        "totalUnpaidAndPendingPayableGwei": <nonnegative integer>
        "totalPaidPayableGwei": <nonnegative integer>
        "totalUnpaidReceivableGwei": <integer>
        "totalPaidReceivableGwei": <nonnegative integer>
    }>,
    "queryResultsOpt":<optional {
        "payableOpt": [
            {
              "wallet": <string>,
              "ageS": <integer>,
              "balanceGwei": <integer>, 
              "pendingPayableHashOpt": <optional string> 
            },
            [...]
        ],
        "receivableOpt": [
            {
              "wallet": <string>,
              "ageS": <integer>,
              "balanceGwei": <integer>
            },
            [...]
        ]
    }>
}
```
##### Description:
Contains the requested financial statistics or subsets (views) of the database tables and their records.

`statsOpt` provides a collection of metrics on services consumed and provided. The current span of the tracked data
is since the start of the still running Node. Later on, we'd like to change it to all-time values.  

`totalUnpaidAndPendingPayableGwei` is the number of gwei we believe we owe to other Nodes and that those other Nodes
have not yet received, as far as we know. This includes both bills we haven't yet paid and bills we have paid, but whose
transactions we have not yet seen confirmed on the blockchain.

`totalPaidPayableGwei` is the number of gwei we have successfully paid to our creditors and seen confirmed.

`totalUnpaidReceivableGwei` is the number of gwei we believe other Nodes owe to us, but have not yet been included in
payments we have seen confirmed on the blockchain. This includes both payments that have never been made and also
payments that have been made but not yet confirmed.

`totalPaidReceivableGwei` is the number of gwei we have successfully received in confirmed payments from our debtors.

`queryResultsOpt` with no respect to which mode of record retrieval was requested, this is always the field that will
hold the records found. If there are no records matching the query, the response will bring an empty array. 

If the `topRecords` parameter is used, the results will be sorted in descending order by either balance or age,
depending on the value of the orderedBy parameter. The number of results returned will be no greater than the value
of the `topRecords` parameter.

With `customQueryOpt`, the limiting age and balance ranges depend on the user's choices and constrain the subset of
records being returned. The results are always ordered by balance in this mode, and it is the case here too, that
an empty array is handed back if no records can be retrieved. 

This query mode is just optional, and it is also a valid option to request just a single table view. Therefore, null
should be anticipated at various places, either at the position of individual tables (`payableOpt`, `receivableOpt`)
or in place of the whole thing (`customQueryOpt`), which implies that a command with these arguments was not used. 

`payableOpt` is the part referring to payable records if any exist, null or an empty array are also possible.

`wallet` is the wallet of the Node that we owe to.

`ageS` is a number of seconds that elapsed since our payment to this particular Node was sent out last time, and the
payment was later also confirmed on the blockchain.

`balanceGwei` is a number of gwei we owe to this particular Node.

`pendingPayableHashOpt` is present only sporadically. When it is, it denotes that we've recently sent a payment to the
blockchain, but our confirmation detector has not yet determined that the payment has been confirmed. The value is
either null or stores a transaction hash of the pending transaction. 

`receivable` is the field devoted to receivable records if any exist.

`wallet` is the wallet of the Node that owes money to us for the services we provided to this Node in the past.

`age` is a number of seconds that elapsed since this particular debtor made the last payment to our account in order to 
redeem his liabilities.

`balanceGwei` is a number of gwei that this debtor owes to us.


#### `generateWallets`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPassword": <string>,
    "seedSpecOpt": {
        "mnemonicPhraseSizeOpt": <optional number>,
        "mnemonicPhraseLanguageOpt": <optional string>,
        "mnemonicPassphraseOpt": <optional string>
    },
    "consumingDerivationPathOpt": <optional string>,
    "earningDerivationPathOpt": <optional string>
}
```
##### Description:
This message directs the Node to generate a pair of wallets and report their vital statistics back to the UI. 
If the database already contains a wallet pair, the wallet generation will fail.

Wallets can be generated in several ways:

* Using derivation paths from a seed: in this case the request should contain a specification for the seed and 
  a derivation path for each wallet, and the response will contain a mnemonic phrase representing the generated
  seed, along with the address and private key for each wallet generated.
* Entirely at random: in this case no direction should be given in the request, and the response will contain
  only the address and private key for each wallet generated.
* With one wallet generated using a seed and a derivation path, and the other generated at random: in this case,
  there should be a specification for the seed and a derivation path for only the seed/path wallet; the other
  wallet will be generated randomly.

`dbPassword` is the current database password. If this is incorrect or absent, the wallet generation will fail.

`seedSpecOpt` gives the parameters for generating the seed. This only makes sense if one or more of the 
derivation paths is supplied. If no derivation paths are supplied, this parameter is ignored.

`mnemonicPhraseSizeOpt` is the number of words that should be generated in the mnemonic phrase. The acceptable values
are 12, 15, 18, 21, and 24. Default is 24.

`mnemonicPhraseLanguageOpt` is the language in which the mnemonic phrase should be generated. Acceptable values are
"English", "Chinese", "Traditional Chinese", "French", "Italian", "Japanese", "Korean", and "Spanish". Default
is "English."

`mnemonicPassphraseOpt`, if specified, is the "25th word" in the mnemonic passphrase: that is, an additional word
(it can be any word; it's not constrained to the official mnemonic-phrase list) that will be used along with the
24 standard words to generate the seed number from which the wallet keys are derived. If this value is supplied,
then the user will have to specify it as well as the 24 standard words in order to recover the wallet pair. Note
that neither the 24 standard words nor this value is persisted anywhere: it's up to the user to keep track of them.
Note also that the "25th word," if generated, is part of the seed and can never be changed: a different "25th word"
will reference a different seed, which means that all wallets derived from it will also be different.

`consumingDerivationPathOpt` if supplied, is the derivation path from the generated seed number to be used to generate
the consuming wallet. By convention, it is "m/44'/60'/0'/0/0", but you can supply whatever path you want. Note that if
you change any of the numbers ending in ', you may have trouble getting other software and hardware to work with your
wallet. If you don't supply `consumingDerivationPathOpt`, your consuming wallet will be generated entirely at random.

`earningDerivationPathOpt` is the derivation path from the generated seed number to be used to generate the earning
wallet. By convention, it is "m/44'/60'/0'/0/1", but you can supply whatever path you want. Note that if
you change any of the numbers ending in ', you may have trouble getting other software and hardware to work with your
wallet. If you don't supply `earningDerivationPathOpt`, your earning wallet will be generated entirely at random.

If the user wants to consume from and earn into the same wallet, he should supply a `seedSpecOpt` and provide the same 
derivation path for both. (Note that just because you direct the Node to generate a mnemonic phrase, you don't
necessarily have to use it. If you need to recover these wallets, you can use their private keys if you don't have
their mnemonic seeds.)

#### `generateWallets`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "mnemonicPhraseOpt": [
        <string>,
        <string>,
        [...]
    ],
    "consumingWalletAddress": <string>,
    "consumingWalletPrivateKey": <string>,
    "earningWalletAddress": <string>,
    "earningWalletPrivateKey": <string>
}
```
##### Description:
This message describes the pair of wallets that has been generated and configured on the Node.

`mnemonicPhraseOpt`, if present, is the requested list of 24 (or 12 or 15 or 18 or 21) words that, when combined with 
the mnemonic passphrase, if present, will produce the seed from which the consuming and earning wallets are derived. 
They are rendered in the requested language, including non-ASCII Unicode characters encoded in UTF-8 where appropriate.

`consumingWalletAddress` is the address of the generated consuming wallet.

`consumingWalletPrivateKey` is the private key of the generated consuming wallet. The Node will retain this key in
its database, in encrypted form, because it needs to withdraw money from the wallet to pay other Nodes in the network.

`earningWalletAddress` is the address of the generated earning wallet.

`earningWalletPrivateKey` is the private key of the generated earning wallet. The Node does not need this key, and
will not retain it; but you'll need it to withdraw earned funds from the wallet, especially if you didn't request or
retain a mnemonic phrase.

#### `logBroadcast`
##### Direction: Broadcast
##### Correspondent: Node
##### Layout:
```
"msg": <String>,
"logLevel": <String>
```
##### Description:
This broadcast intends to give the user an immediate notification about a significant event that just occurred in
the Node. At a bit lower level, this is a reaction to when the execution flow crosses any place with logging that bears
a severity of `Info`, `Warn` or `Error`. Every such situation produces this broadcast along with the usual,
long-adopted way of writing a log into a file and so both happen simultaneously. 

Certain plans are to diverge between what is going to be printed to the log file and what is going to be given to
the UI, while the latter in a prettier and user-friendlier form, but more preparation must go before we can implement
that. 

The log level constraining the UI output from less important messages (`Debug` and `Trace`) is now steadily given 
by the `Info` level. However, we may consider make it adjustable if there is a demand like that.

`msg` is the message describing a passed event. 

`logLevel` indicates what severity the reported event had. It can only be a string from this list: `Info`, `Warn`,
`Error`.

#### `newPassword`
##### Direction: Broadcast
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
No data comes with this message; it's merely used to inform a UI that the database password has changed.
If the UI is remembering the database password, it should forget it when this message is received.

#### `recoverWallets`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPassword": <string>,
    "seedSpecOpt": {
        "mnemonicPhrase": [
            <string>,
            <string>,
            [...]
        ],
        "mnemonicPhraseLanguageOpt": <optional string>,
        "mnemonicPassphraseOpt": <optional string>
    },
    "consumingDerivationPathOpt": <optional string>,
    "consumingPrivateKeyOpt": <optional string>,
    "earningDerivationPathOpt": <optional string>,
    "earningAddressOpt": <optional string>,
}
```
##### Description:
This message directs the Node to set its wallet pair to a preexisting pair of wallets described in the message.
If the database already contains a wallet pair, the wallet recovery will fail.

Each wallet can be recovered in one of two ways.

The consuming wallet can be recovered by specifying the mnemonic phrase of its seed and its derivation path, or by
giving its private key. (The Node needs the private key of the consuming wallet so that it can withdraw funds from it
to pay bills.)

The earning wallet can be recovered by specifying the mnemonic phrase of its seed and its derivation path, or by
giving its address. (The Node does not need (and will not accept) the private key of the earning wallet, because all
it ever has to do is deposit funds in it from other Nodes. The private key can be derived from the seed and the
derivation path, but the Node does not store it.)

This message schema allows you to provide more information than is necessary: for example, both earning address
and earning derivation path (which may conflict), or both consuming private key and consuming derivation path
(which also may conflict). If you do so, the derivation path will be overridden by the key or address and ignored.

If you expect the derivation path to be used for either wallet, you must also provide the seed specification.

`dbPassword` is the current database password. If this is incorrect, the wallet recovery will fail.

`seedSpecOpt` gives the parameters for generating the seed. This only makes sense if one or more of the
derivation paths is supplied. If no derivation paths are supplied, this parameter is ignored.

`mnemonicPhrase` is the mnemonic phrase that represents the seed. It must have 12, 15, 18, 21, or 24 words.

`mnemonicPhraseLanguageOpt` is the language in which the mnemonic phrase is supplied. Acceptable values are
"English", "Chinese", "Traditional Chinese", "French", "Italian", "Japanese", "Korean", and "Spanish". Default
is "English."

`mnemonicPassphraseOpt`, if specified, is the "25th word" in the mnemonic passphrase: that is, an additional word
(it can be any word; it's not constrained to the official mnemonic-phrase list) that was used along with the
words of the mnemonic phrase to generate the seed number from which the consuming and possibly earning wallets
were derived. If no mnemonic passphrase was used to generate the wallets, this value must be null or absent.

`consumingDerivationPathOpt`, if supplied, is the derivation path from the generated seed number to be used to generate
the consuming wallet. By convention, it is "m/44'/60'/0'/0/0", but you can supply whatever path you want. Note that if
you change any of the numbers ending in ', you may have trouble getting other software and hardware to work with your
wallet. If you don't supply `consumingDerivationPathOpt`, you must supply `consumingPrivateKeyOpt`.

`consumingPrivateKeyOpt`, if specified, is the private key of the consuming wallet, represented as a string of 64
hexadecimal digits. This value supersedes `consumingDerivationPathOpt` if both are supplied; but if you don't supply 
that value, you must supply this one.

`earningDerivationPathOpt` is the derivation path from the generated seed number to be used to generate the earning
wallet. By convention, it is "m/44'/60'/0'/0/1", but you can supply whatever path you want. Note that if
you change any of the numbers ending in ', you may have trouble getting other software and hardware to work with your
wallet. If you don't supply `earningDerivationPathOpt`, you must supply `earningAddressOpt`.

`earningAddressOpt`, if specified, is the address of the earning wallet, represented as "0x" followed by a string
of 40 hexadecimal digits. This value supersedes `earningDerivationPathOpt` if both are supplied; but if you don't 
supply that value, you must supply this one.

The consuming and earning wallet information may evaluate to the same wallet; there's nothing wrong with that.

#### `recoverWallets`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
This message acknowledges that the Node's wallet pair was set as specified.

#### `redirect`
##### Direction: Unsolicited Response
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "port": <positive integer>,
    "opcode": <string>,
    "contextId": <optional positive integer>,
    "payload": <string>,
}
```
##### Description:
This message will be sent by the Daemon to a UI in response to a message with an opcode the Daemon doesn't
recognize, when the Node is running. The Daemon's assumption is that such a message must be meant for the Node.

The `port` field contains the port number on which the Node is listening for UI connections.

The `opcode` field contains the opcode of the unrecognized message.

The `contextId` field, if present, contains the `contextId` of the unrecognized message. If not present, then
the unrecognized message was not part of a conversation.

The `payload` field is a string of JSON, containing the payload of the unrecognized message.

The UI should disconnect from the Daemon, connect to the Node on `localhost` at the indicated port,
reconstruct the original message from the `opcode`, `contextId`, and `payload` fields, and send it to the
Node.

#### `scan`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "name": <string>
}
```
##### Description:
This message instructs the Node to perform a payables scan, a pending-payables scan, or a receivables scan, depending 
on the `name` parameter. This will be an extra, additional scan and will not affect the Node's regular schedule of 
autonomous scans, if any, except that it's possible that it may delay a regular autonomous scan if the Node is busy 
with your scan when the autonomous scan is scheduled.

The `name` field in the payload must be "payables" or "pendingpayables" or "receivables".

A payables scan will search through the database for payable bills that are big enough and old enough to pay, and will 
pay them from your consuming wallet. A pending-payables scan will find payments you've already made on the blockchain
that have since been confirmed--actually received by your creditors--and remove them from your books. A receivables 
scan will do two things: first, it will scan the blockchain for receivables that have been paid to your earning wallet, 
and adjust your books to reflect those payments; second, it will run a database scan to handle delinquency banning and 
unbanning.

#### `scan`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
}
```
##### Description:
This is a simple acknowledgment that the requested scan has been completed.

#### `setConfiguration`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "name": <string>,
    "value": <string>
}
```
*Note: the design of this message is likely to change in the future. A field for the database password will appear. 
At the current time, there are no parameters requiring the password among those supported by this command.*

##### Description:
This is a message used to change a parameter whilst the Node is running. The range of supported parameters (available
to be set by this command) may get larger with time.

The `name` field in the payload is the name of the parameter which the user wants to modify and has this form:
e.g. start-block or gas-price (with a dash between words).

The `value` field in the payload is the value to be assigned to the parameter. It must always be specified as a string,
even for parameters whose values are natively of other types.  

#### `setConfiguration`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
}
```
##### Description:
If the value of the respective parameter was successfully changed, this is a simple acknowledgment that the change is complete.

The following commands can be configured using the `setConfiguration`:


| Name             | Parameter       | Possible Values  |
|------------------|-----------------|------------------|
| Gas Price        | `--gas-price`   | > 0              |
| Start Block      | `--start-block` | > 0              |
| Min Hops         | `--min-hops`    | [1, 6]           |


Note: The descriptions for the above commands can be found [here](#permitted-names).

#### `setup`
##### Direction: Request
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "values": [
        {
            "name": <string, see below>,
            "value": <optional string>
        },
        < ... >
    ]
}
```
##### Description:
Requests modifications to the Daemon's Setup space and a dump of the results.

The `values` array may be empty. If it is, no modifications will be made, but a report of the existing contents
of the Setup space will be returned.

The `name` field is one of a set of known parameter names whose value should be changed. See below for a list.

The `value` field, if present, holds the new value for the parameter. If not present, the parameter value will
be cleared.

###### Permitted `name`s
* `blockchain-service-url` - URL of the blockchain service to use: currently only Infura is supported.
* `chain` - `mainnet` or `ropsten`. The blockchain the Node should connect to. 
* `clandestine-port` - The port at which other Nodes will contact this one.
* `config-file` - Path to or name of the TOML file from which to take additional configuration.
* `consuming-private-key` - 64-digit hexadecimal number containing the consuming wallet's private key.
* `data-directory` - Path to data directory.
* `db-password` - Password to unlock the sensitive values in the database.
* `dns-servers` - Comma-separated list of DNS servers to use.
* `earning-wallet` - Wallet into which earnings should be deposited.
* `entry-dns` - To start MASQ's local DNS server if HTTP proxying is unavailable.
* `gas-price` - The fee per unit of computational effort in blockchain transactions, measured in gwei.
* `ip` - The public IP address of the Node.
* `log-level` - The lowest level of logs that should be recorded. `off`, `error`, `warn`, `info`, `debug`, `trace`
* `mapping-protocol` - The management protocol to try first with the router. `pcp`, `pmp`, `igdp`
* `min-hops`: The minimum number of hops required for the package to reach the Exit Node.
* `neighborhood-mode` - `zero-hop`, `originate-only`, `consume-only`, `standard`
* `neighbors` - Comma-separated list of Node descriptors for neighbors to contact on startup
* `real-user` - Non-Windows platforms only, only where required: <uid>:<gid>:<home directory>

#### `setup`
##### Direction: Response or Broadcast
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "running": <boolean>,
    "values": [
        {
            "name": <string>,
            "value": <string>,
            "status": <string, see below>,
        },
        < ... >
    ],
    "errors": [
        [<string, see below>, <string, see below>],
        < ... >
    ]
}
```
##### Description:
Conveys the contents of the Daemon's Setup space. A UI will receive this message as a response (with a
meaningful `contextId`) if it sends a `setup` request; but it will also receive this message as an unsolicited
broadcast if another UI sends a `setup` request that results in actual changes to the Daemon's Setup space.

The `running` field will be true if the Node is currently running, or false otherwise. If true, the proposed
changes, if any, in the request that stimulated this response or broadcast were ignored, because the Setup
space is immutable while the Node is running.

The `values` array contains a list of the values in the Setup space. For each object in the list:

The `name` field is the name of the parameter, one of the names listed for the request above.

The `value` field is the value of that parameter. If the parameter has no value, the `value` field will be
a blank string.

The `status` field has one of the following values:
* `Default` - The parameter has a default value, and has not been changed from it.
* `Configured` - The parameter has taken its value from a configuration file or an environment variable.
* `Set` - The parameter was set by a UI using a `setup` message.
* `Blank` - The parameter has no value, and no value is required.
* `Required` - The parameter has no value, but some value is required to start the Node.

Sometimes, the values in the Setup space may be incomplete, inconsistent, or obviously incorrect. When this
happens, the `errors` array will be populated with error messages about the problem parameters. It's an array
of two-element arrays; each two-element array will have the name of the offending parameter first, and an
appropriate error message second. If there are no detectable errors, the `errors` array will be empty.

The presence of errors or `Required` parameters will not prevent the Daemon from attempting to start the Node,
but it will prevent the Node from starting or running properly. The UI may choose not to offer the user the
option to start the Node until the Daemon is happy, but that's optional.

#### `shutdown`
##### Direction: Request or Response
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
The `shutdown` message has an empty payload. As a Request, it instructs the Node to shut down. As a Response, it
notifies the UI that the Node is almost shut down. (Obviously, the Node can't send a Response if it's _completely_
shut down.)

#### `start`
##### Direction: Request
##### Correspondent: Daemon
##### Layout:
```
"payload": {}
```
##### Description:
The `start` message has an empty payload. It causes the Daemon to try to start the Node with whatever configuration
information is presently in its Setup space.

#### `start`
##### Direction: Response
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "newProcessId": <integer>,
    "redirectUiPort": <integer greater than 1024>,
}
```
##### Description:
If a `start` attempt is successful, this response will arrive.

The `newProcessId` field is the system-dependent process ID of the newly-running Node.

The `redirectUiPort` field is the WebSockets port on which the UI can now connect to the Node. The UI that actually
starts the Node can take advantage of this to preemptively connect to the Node without processing a Redirect; but
a UI that starts after the Node is already running must go through the Redirect operation to find it. It requires
less code to simply have your UI always use Redirects.

Because the Daemon is not allowed to communicate with the Node for security reasons, the Daemon cannot know
the Node's Node descriptor; therefore it cannot be included in the response to the `start` request. To
discover a newly-started Node's Node descriptor, send the `descriptor` message directly to the Node itself.

#### `unmarshalError`
##### Direction: Response
##### Correspondent: Daemon or Node
##### Layout:
```
"payload": {
    "message": <string>,
    "badData": <string>,
}
```
##### Description:
If the Daemon or the Node can't unmarshal a message from a UI, it will send this message in response.

The `message` field describes what's wrong with the unmarshallable message.

The `badData` field contains the unmarshallable message itself.

#### `walletAddresses`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPassword": <string>
}
```
##### Description:
This message asks the Node for the earning and consuming wallet addresses. The consuming wallet address will be 
computed from the mnemonic seed and the recorded derivation path chosen by the user earlier. The mnemonic seed is
secret, which is why this message requires the `dbPassword` element. If one or both wallets are not configured, 
an error message will be sent back.

#### `walletAddresses`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "consumingWalletAddress": <string>,
    "earningWalletAddress": <string>
}
```
##### Description:
This message carries the pair of wallet addresses that were generated or recovered in the past.

`consumingWalletAddress` is the address of the generated consuming wallet.

`earningWalletAddress` is the address of the generated earning wallet.
