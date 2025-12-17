package confparser

type ClientConfig struct {
	OperationID    string `json:"operationID" yaml:"operationID"`
	SendID         string `json:"sendID" yaml:"sendID"`
	ReceiveID      string `json:"receiveID" yaml:"receiveID"`
	SenderNickname string `json:"senderNickname" yaml:"senderNickname"`
	Token          string `json:"token" yaml:"token"`
	ServerAddr     string `json:"serverAddr" yaml:"serverAddr"`
}
