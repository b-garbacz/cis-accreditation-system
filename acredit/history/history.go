package history

import "myapp/token"

type History_object struct {
	TxId  string              `json:"txid"`
	Value *token.Audit_result `json:"value"`
}
