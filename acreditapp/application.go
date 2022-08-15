package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

//source https://github.com/hyperledger/fabric-samples/tree/main/asset-transfer-basic/chaincode-go
func populateWallet(wallet *gateway.Wallet) error {
	log.Println("============ Populating wallet ============")
	credPath := filepath.Join(
		"..",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"users",
		"User1@org1.example.com",
		"msp",
	)

	certPath := filepath.Join(credPath, "signcerts", "cert.pem")
	// read the certificate pem
	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return err
	}
	keyDir := filepath.Join(credPath, "keystore")
	// there's a single file in this dir containing the private key
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return fmt.Errorf("keystore folder should have contain one file")
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return err
	}

	identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))

	return wallet.Put("appUser", identity)
}

//source fabric-samples/asset-transfet-basic/application-go
func turn_on_connection() *gateway.Contract {
	err := os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
	if err != nil {
		log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environment variable: %v", err)
	}

	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	if !wallet.Exists("appUser") {
		err = populateWallet(wallet)
		if err != nil {
			log.Fatalf("Failed to populate wallet contents: %v", err)
		}
	}

	ccpPath := filepath.Join(
		"..",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"connection-org1.yaml",
	)

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "appUser"),
	)

	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	contract := network.GetContract("basic")
	return contract
}

func begin_audit(contract *gateway.Contract, ip string, username string, password string) {
	fmt.Println("--------------------BEGIN AUDIT--------------------")
	result, err := contract.SubmitTransaction("StartAudit", ip, username, password)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	} else {
		fmt.Println("The security audit was successfully completed")
	}
	if result != nil {
		log.Fatalf("Failed: %v", result)
	}

	result, err = contract.EvaluateTransaction("QueryToken", ip)
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	fmt.Println(string(result))

	fmt.Println("--------------------AUDIT HAS BEEN ENDED--------------------")

}

func check_history_of_token(contract *gateway.Contract, ip string) {
	fmt.Println("--------------------CHECK HISTORY OF TOKEN--------------------")
	result, err := contract.EvaluateTransaction("QueryTokenHistory", ip)
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}

	fmt.Println(string(result))
	fmt.Println("--------------------CHECK HISTORY OF TOKEN--------------------")

}

func main() {
	ip := os.Args[1]
	username := os.Args[2]
	password := os.Args[3]
	contract := turn_on_connection()
	begin_audit(contract, ip, username, password)
	check_history_of_token(contract, ip)
}
