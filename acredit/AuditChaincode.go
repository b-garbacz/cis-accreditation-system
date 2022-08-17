package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"myapp/audit"
	"myapp/history"
	"myapp/token"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

/*
	Smart Contract interface
*/
type SmartContract struct {
	contractapi.Contract
}

/*
	StartAudit Contract takes 2 inputs:
	1.ip (string)
	2. username (string)
	3. passwrd (string)

	This contract performs a security audit by using Get_version_name().
	Get_version_name() function connects to the instance via SSH and checks security rules. If the safety tests performed are correct
	then it returns nil, otherwise it returns error if instance is not secured.Error contains name of incorect tested? security rule.
	If the audit fails then world state is not updated.

	If the security audit is correct then generate token(without digital signature) and put it to the state {Key:ip , Value:ready_to_ledger} where ready_to_ledger is a generated token


*/
func (s *SmartContract) StartAudit(ctx contractapi.TransactionContextInterface, ip string, username string, passwrd string) error {
	var errstring string
	device := audit.Device{Ip: ip, Username: username, Passwrd: passwrd}
	err := audit.Get_version_name(&device)
	if err != nil {
		return err
	}
	errstring, err = audit.Check_all_rules(&device)
	if err != nil {
		return errors.New(errstring + "! " + err.Error())
	}
	var message token.Message
	var audit_res token.Audit_result
	rule := "Technical-and-Implementation-Directive-on-CIS-Security-2019"
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	message.Build_message(device.Ip, device.Username, device.Version)
	token, err := token.Get_Cert(&message, rule, timestamp.Seconds)
	if err != nil {
		return err
	}
	audit_res.Build_Audit_Result(token, &message, rule, timestamp.Seconds)
	ready_to_ledger, err := json.Marshal(audit_res)
	if err != nil {
		return errors.New("JSON Marshal error")
	}
	return ctx.GetStub().PutState(device.Ip, ready_to_ledger)
}

/*
	QueryToken Contract takes 1 input:
	1.ip (string)
	This contract finds the state of token by IP value and returns state of audit_result and error. Where audit_result is a token
*/
func (s *SmartContract) QueryToken(ctx contractapi.TransactionContextInterface, ip string) (*token.Audit_result, error) {
	audit_result_bytes, err := ctx.GetStub().GetState(ip)
	if err != nil {
		return nil, fmt.Errorf("Failed to read from world state. %s", err.Error())
	}
	if audit_result_bytes == nil {
		return nil, fmt.Errorf("%s does not exist", ip)
	}
	audit_result := new(token.Audit_result)
	_ = json.Unmarshal(audit_result_bytes, &audit_result)
	return audit_result, nil

}

/*
	QueryTokenHistory Contract takes 1 input:
	1.ip (string)
	This contract returns a history of token changes
*/
func (s *SmartContract) QueryTokenHistory(ctx contractapi.TransactionContextInterface, ip string) (string, error) {
	var history_array []*history.History_object               // create array as history_object type from history module
	query_iterator, err := ctx.GetStub().GetHistoryForKey(ip) // Get asset history of changes
	if err != nil {
		return "", err
	}
	defer query_iterator.Close()
	// "HasNext returns true if the range query iterator contains additional keys
	// and values." https://pkg.go.dev/github.com/hyperledger/fabric-chaincode-go/shim#CommonIterator.HasNext
	for query_iterator.HasNext() {
		history_item, err := query_iterator.Next()
		if err != nil {
			return "", err
		}

		history_object := new(history.History_object)
		history_object.TxId = history_item.TxId
		audit_result := new(token.Audit_result)
		err = json.Unmarshal(history_item.Value, &audit_result)
		if err != nil {
			return "", err
		}

		history_object.Value = audit_result

		history_array = append(history_array, history_object)
		history_object = nil
	}

	all_data, err := json.Marshal(history_array)
	if err != nil {
		return "", err
	}

	return string(all_data), nil
}
func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating chaincode: %s", err.Error())
		return
	}
	err = chaincode.Start()
	if err != nil {
		fmt.Printf("Error starting chaincode: %s", err.Error())
	}

}
