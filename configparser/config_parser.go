package confparser

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/stretchr/testify/assert/yaml"
)

type Parser interface {
	ParseFromConfigFile() (*ClientConfig, error)
}

type JsonParser struct {
	configPath string
}

type YamlParser struct {
	configPath string
}

// 没有返回接口指针的用法，返回结构体指针对应接口
func NewParser(configPath string) Parser {
	// 获取后缀
	fileExt := filepath.Ext(configPath)
	fileExt = strings.ToLower(fileExt)

	// 根据文件后缀返回不同的解析器
	switch fileExt {
	case ".json":
		return &JsonParser{configPath: configPath}
	case ".yaml":
		return &YamlParser{configPath: configPath}
	}
	return nil
}

func (j *JsonParser) ParseFromConfigFile() (*ClientConfig, error) {
	// 读取配置文件内容
	file, err := os.Open(j.configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 解析 JSON 内容
	var config ClientConfig
	err = json.NewDecoder(file).Decode(&config)
	if err != nil {
		return nil, err
	}

	// 参数检查
	if config.OperationID == "" || config.SendID == "" || config.ReceiveID == "" || config.SenderNickname == "" || config.Token == "" || config.ServerAddr == "" {
		return nil, fmt.Errorf("operationID, sendID, token, serverAddr are required")
	}

	return &config, nil
}

func (y *YamlParser) ParseFromConfigFile() (*ClientConfig, error) {
	// 读取配置文件内容
	// os.Open 返回的是 io.Reader
	// os.ReadFile 返回的是 []byte
	file, err := os.ReadFile(y.configPath)
	if err != nil {
		return nil, err
	}

	// 解析 YAML 内容
	var config ClientConfig
	// 需要输入的时字节流而不是 o.Reader
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	log.Printf("config: %v", config)
	log.Printf("config.senderNickname: %s", config.SenderNickname)
	// 参数检查
	if config.OperationID == "" || config.SendID == "" || config.ReceiveID == "" || config.SenderNickname == "" || config.Token == "" || config.ServerAddr == "" {
		return nil, fmt.Errorf("operationID, sendID, receiveID, senderNickname, token, serverAddr are required")
	}

	return &config, nil
}
