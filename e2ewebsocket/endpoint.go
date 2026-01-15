package e2ewebsocket

import (
	"sync"

	"github.com/gorilla/websocket"
)

// Endpoint: 负责物理连接和分发
type Endpoint struct {
	conn *websocket.Conn

	// 只用一个 map 管理所有会话
	sessions sync.Map // map[string]*Session
}
