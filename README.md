# cis-accreditation-system
It is the implementation of a system that enables the performance of a security audit, which is an integral part of the accreditation process, in order to process classified information using a private blockchain and smart contracts.
<br>
:file_folder: acredit - includes chaincode that enable the security audit <br>
:file_folder: acreditapp - includes a compiled(client application) program that allows to send a transaction proposal for a security audit <br>
:file_folder: test-network - this is the primary test network provided by hyperledger Fabric developers.<br>
# Chaincode installation <br>
Go to the test-network directory and run the start_script.sh script to create test network with installed chaincode
# Launching the client application <br>
Before launching the client application you have to create EC2 instance on AWS with password authentication and configure the operating system(
check the check.go directory to see to see the security rules which are checked). Example below:<br>
![image](https://user-images.githubusercontent.com/45511879/189539825-4252cf14-98d7-48fe-9b3a-f1afa01ace7a.png)


