package token

import (
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
)

/*Token structure from audit result*/
type Audit_result struct {
	Certificate  string  `json:"certificate"`
	Message      Message `json:"message"`
	Set_of_rules string  `json:"set_of_rules"`
	Timestamp    int64   `json:"timestamp"`
}
type Message struct {
	Ip       string `json:"ip"`
	Username string `json:"username"`
	Version  string `json:"version"`
}

func (m *Message) Build_message(ip string, username string, version string) {
	m.Ip = ip
	m.Username = username
	m.Version = version
}

func (ar *Audit_result) Build_Audit_Result(certificate string, mess *Message, set_of_rules string, timestamp int64) {
	ar.Certificate = certificate
	ar.Message = *mess
	ar.Set_of_rules = set_of_rules
	ar.Timestamp = timestamp
}

/*
	The certificate(Audit_result) is the result of a correct audit result
	If the security audit was carried out correctly, generate a certificate
	The certificate consists of a message, set of rules, and a timestamp(unix). The certificate is a string type.
	certificate = BASE64(BYTE(Message)).BASE64(BYTE(set_of_rules)).BASE64(BYTE(timestamp))
	certificate and error are returned
*/
func Get_Cert(mess *Message, set_of_rules string, timestamp int64) (string, error) {
	//MessageEncoding
	message_encode_json, err := json.Marshal(mess) //encode to bytes  as json
	if err != nil {
		return "", errors.New("JSON Marshal error")
	}
	message_encode_base64 := b64.StdEncoding.EncodeToString(message_encode_json) // encode bytes to base64

	//Set of rules encoding
	set_of_rules_base64 := b64.StdEncoding.EncodeToString([]byte(set_of_rules)) // encode string to base64

	//timestamp Encoding   https://stackoverflow.com/questions/35371385/how-can-i-convert-an-int64-into-a-byte-array-in-go
	b_timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(b_timestamp, uint64(timestamp))
	timestamp_base64 := b64.StdEncoding.EncodeToString(b_timestamp)                    //encode timestamp to base64
	cert := message_encode_base64 + "." + set_of_rules_base64 + "." + timestamp_base64 //Create unsigned certificate
	return cert, nil
}
