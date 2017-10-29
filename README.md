# Atom

Atom is an anonymous broadcasting system that allows users to send short
messages while preserving their anonymity. This is particularly useful for
things like anonymous whistleblowing and protest organization, where the sender
may fear retaliation from powerful adversaries for sending certain messages.
Atom is the first anonymous communication system that scales horiztonally while
protecting against traffic analysis by global adversaries. Our 
[SOSP'17 paper](http://people.csail.mit.edu/devadas/pubs/atom.pdf) 
explains the system in detail.

The code posted here is a *research prototype*. While the code performs all the
necessary crypto operations and should be fairly accurate in terms of
performance, it is likely full of security bugs and security-criticial TODOs
that hasn't been addressed. Pleae be careful if any part of this code is reused
for other projects.

## Requirements

The code requires Go 1.7 or later. The scripts are written in python. Most of
the crypto operation relies on the [DeDiS kyber
library](https://github.com/dedis/kyber).

## Components

* crypto: This implements all crypto operations used by Atom. There is a level
of indirection from here to the kyber library, so that we can easily replace
the crypto section of Atom without impacting rest of the code base.

* server: This implements both a physical server, and a logical server (member)
which can be part of many groups. This part of the code actually carries out
the protocol.

* client: Client program handles sending of the messages. Currently, each client
program is responsible for sending many messages. From user's perspective, only
Submit function should be relavant.

* directory: This is a very simple directory that keeps track of all
participants and their keys.

* trustee: Trustees are only used in one variant of our protocol, and they serve
as the final line of protection for users.

* db: This is a very simple database that stores all messages published in a
given round so that users can download them.

## Running the code

To create all the executable, run

   $ go install ./...

in the root folder.

There is an integration test availble in `atom_test.go`. This serves as both an
example of the overall flow, and a test function. You can run this simply by
doing

    $ go test -v

in the root atom folder.

We also provide a way, `run.py`, to start individual processes, both local and
remote, to test the code, rather than using the go test which just uses go
routines. To run this, you first have to generate enough keys by running
something like

    $ mkdir $GOPATH/src/github.com/kwonalbert/atom/keys
    $ $GOPATH/bin/keygen -numServers 1024 -numTrustees 32 -serverKeys $GOPATH/src/github.com/kwonalbert/atom/keys/server_keys.json -trusteeKeys $GOPATH/src/github.com/kwonalbert/atom/keys/trustee_keys.json

The same keys can be used for all experiments afterwards. Once the keys are set
up, you are ready to run `run.py`. Running

    $ run.py --help

will give you all available options. For example, the following command

    $ /run.py --port 8000 --servers 8 --gsize 4 --groups 4 --clients 4 --trustees 4 --msgs 16 --msize 160 --type 1 --mode 1

runs a local Atom experiment with

* 16 servers
* 4 groups
* 4 trustees
* 16 messages per group
* 160 byte messages
* square network
* trap based protection.

## Known problems and limitations

The current implementation just runs one round. There is some work that needs
to be done to extend this code to do multiple rounds of communication.

This code was *very* recently migrated to the kyber library (from the old DeDiS
library), and I've caught some weird bugs that arose as a result. I tried to
squash as many as I could, but I think there are some more. If you run into
them, please let me know. The current code uses ed25519 instead of nist-p256,
since that portion of the code is not compiled by default in the new kyber library.

The script provided is very simple, and does not do fancy things for AWS;
currently you need to have a separate script to set up your AWS network, and
give in the instance description (from `aws ec2 describe-instances`) to the
script to run it on AWS.

## Contacts

If you have any problems with the code or want to learn more about it, don't
hesitate to contact me at `kwonal at mit.edu`, or file an issue here.
