////go:build client

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/albert/ws_client/compressor"
	confparser "github.com/albert/ws_client/configparser"
	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"

)

var configPath string

func init() {
	flag.StringVar(&configPath, "config", "./config/client.json", "配置文件路径")
}

func main() {

	// 获取编译参数
	flag.Parse()

	configParser := confparser.NewParser(configPath)
	if configParser == nil {
		log.Fatalf("不支持的配置文件格式: %s", configPath)
	}
	config, err := configParser.ParseFromConfigFile()
	if err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}

	// 1. 构建目标 WebSocket 链接（包含所有参数）
	wsURL := config.ServerAddr
	// 解析基础 URL
	parsedURL, err := url.Parse(wsURL)
	if err != nil {
		log.Fatalf("解析 URL 失败: %v", err)
	}

	//ws://192.168.1.72:10001?
	// sendID=2800935371
	// &token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySUQiOiIyODAwOTM1MzcxIiwiUGxhdGZvcm1JRCI6NSwiZXhwIjoxNzcyNzAxMjI4LCJpYXQiOjE3NjQ5MjUyMjN9.74_BGPl_T8_x09Wcfjv2O7DnkocVYQ2pHL10ltuXjnM
	// &platformID=5
	// &operationID=1764923222622312981
	// &isBackground=false
	// &compression=gzip

	// 2. 设置 URL 参数（与目标链接一致）
	params := url.Values{}
	params.Set("compression", "gzip")
	params.Set("isBackground", "false")
	params.Set("isMsgResp", "true")
	params.Set("operationID", config.OperationID)
	params.Set("platformID", "5")
	params.Set("sendID", config.SendID)
	params.Set("token", config.Token)

	// 将参数拼接到 URL
	parsedURL.RawQuery = params.Encode()

	// 3. 打印最终连接地址（验证参数是否正确）
	log.Printf("正在连接 WebSocket 服务器: %s", parsedURL.String())

	// 4. 配置 Dialer（可自定义超时、代理等）
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second, // 握手超时
		// 如需跳过证书验证（仅测试环境）：
		// TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 5. 发起 WebSocket 连接（携带自定义 Header，可选）
	headers := make(map[string][]string)
	// 如果服务端需要额外 Header，可在此添加
	// headers["Authorization"] = []string{"Bearer " + token}
	conn, resp, err := dialer.Dial(parsedURL.String(), headers)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	// 打印握手响应（便于调试）
	log.Printf("连接成功，服务端响应状态码: %d", resp.StatusCode)

	// 8. 控制台输入交互
	scanner := bufio.NewScanner(os.Stdin)
	log.Println("连接已建立，输入消息回车发送（输入 exit 退出）")

	// 压缩器
	compressor := compressor.NewGzipCompressor()
	// 编码器【要用Gob】
	encoder := encoder.NewGobEncoder()

	// MsgData 构造
	msgBuilder := NewBuilder(config.SendID, config.ReceiveID, config.SenderNickname, encoder, compressor)

	// 因为想要公用主线程发送的压缩器和编码器，所以把读取消息的 goroutine 放到这里
	// 6. 启动协程监听服务端消息
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			// 读取服务端消息
			// log.Printf("===读取服务端消息===")
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("读取消息失败: %v", err)
				return
			}

			// 根据消息类型处理
			switch msgType {
			case websocket.TextMessage:
				log.Printf("[文本消息] 收到服务端回复: %s", string(msg))
				// if err := conn.WriteMessage(websocket.BinaryMessage, []byte("")); err != nil {
				// 	log.Printf("立即发一个Binary消息失败: %v", err)
				// 	return
				// }
				// log.Printf("立即发送一个Binary消息成功")

				// if err := conn.WriteMessage(websocket.PingMessage, []byte("")); err != nil {
				// 	log.Printf("立即发一个Ping消息失败: %v", err)
				// 	return
				// }
				// log.Printf("立即发送一个Ping消息成功")
			case websocket.BinaryMessage:
				log.Printf("[二进制消息] 收到服务端数据，长度: %d", len(msg))
				// 解析消息
				conversationIds, contentList, err := parseMsg(msg, compressor, encoder)
				if err != nil {
					log.Printf("解析消息失败: %v", err)
					continue
				}
				for i := 0; i < len(conversationIds); i++ {
					log.Printf("From会话[%s]收到消息: %s", conversationIds[i], contentList[i])
				}
				log.Printf("共收到 %d 条消息", len(conversationIds))

			case websocket.PingMessage:
				log.Println("收到服务端 Ping，回复 Pong")
				// 自动回复 Pong
				if err := conn.WriteMessage(websocket.PongMessage, nil); err != nil {
					log.Printf("回复 Pong 失败: %v", err)
					return
				}
			case websocket.PongMessage:
				log.Println("收到服务端 Pong，连接正常")
			case websocket.CloseMessage:
				log.Printf("收到服务端关闭连接: %s", string(msg))
				return
			default:
				log.Printf("收到未知类型消息，类型码: %d", msgType)
			}
		}
	}()

	for {
		select {
		case <-done:
			// 监听协程退出，程序结束
			log.Println("连接已关闭，程序退出")
			return

		default:
			// 读取用户输入
			fmt.Print("> ")
			if !scanner.Scan() {
				log.Println("读取输入失败，退出")
				return
			}

			input := scanner.Text()
			if input == "exit" {
				// 主动关闭连接
				log.Println("发送关闭连接请求")
				closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "客户端主动退出")
				if err := conn.WriteMessage(websocket.CloseMessage, closeMsg); err != nil {
					log.Printf("发送关闭消息失败: %v", err)
				}
				// 等待 1 秒后退出
				time.Sleep(1 * time.Second)
				return
			}

			// 不退出则处理输入

			msgBuilder.OfflinePushInfo().MsgData(input)

			// protobuf 序列化
			msgBytes, err := proto.Marshal(msgBuilder.msgData)
			if err != nil {
				log.Printf("序列化消息失败: %v", err)
				return
			}

			// Req 构造
			msgBuilder = msgBuilder.Req(msgBytes)

			// 编码+压缩
			msg := msgBuilder.Build()

			// 发送文本消息
			// if err := conn.WriteMessage(websocket.TextMessage, []byte(input)); err != nil {
			if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
				log.Printf("发送消息失败: %v", err)
				return
			}
			log.Printf("已发送消息: %s", input)
		}
	}
}

func parseMsg(msg []byte, compressor compressor.Compressor, encoder encoder.Encoder) ([]string, []string, error) {

	// 解压
	decompressMsg, err := compressor.DecompressWithPool(msg)
	if err != nil {
		log.Printf("解压消息失败: %v", err)
		return nil, nil, err
	}

	// 解码
	var resp Resp
	err = encoder.Decode(decompressMsg, &resp)
	if err != nil {
		log.Printf("解码消息失败: %v", err)
		return nil, nil, err
	}

	var pushMsg sdkws.PushMessages
	// 反序列化到 PushMessages 结构体
	err = proto.Unmarshal(resp.Data, &pushMsg)
	if err != nil {
		log.Printf("反序列化消息失败: %v", err)
		return nil, nil, err
	}

	conversationIds := make([]string, 0, 1)
	contentList := make([]string, 0, 1)

	msgMap := pushMsg.Msgs
	// 虽然是循环，但是单聊的时候 map 里只会有一个会话
	for conversationId, pullMsg := range msgMap {
		// 一个会话里可能有多个消息，但单聊的时候一般只有一个
		for _, msgData := range pullMsg.Msgs {
			var recvMsg Message
			err := json.Unmarshal(msgData.Content, &recvMsg)
			if err != nil {
				log.Printf("解析Json消息失败: %v", err)
				return nil, nil, err
			}
			// log.Printf("From会话[%s]收到消息: %s", conversationId, recvMsg.Content)
			conversationIds = append(conversationIds, conversationId)
			contentList = append(contentList, recvMsg.Content)
		}
	}
	return conversationIds, contentList, nil
}
