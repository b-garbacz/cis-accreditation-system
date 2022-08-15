#!/bin/bash
# Enable the network in hyperledger fabric
./network.sh down
./network.sh up createChannel -c mychannel -ca -s couchdb -ccep "AND('Org1.peer', 'Org2.peer')"
./network.sh deployCC -ccn basic -ccp ../acredit -ccl go
