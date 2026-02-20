package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for embedded dashboard
	},
}

// WSClient represents a connected WebSocket client.
type WSClient struct {
	conn   *websocket.Conn
	send   chan []byte
	hub    *WSHub
	filter string
}

// WSHub manages WebSocket connections and broadcasts.
type WSHub struct {
	mu         sync.RWMutex
	clients    map[*WSClient]bool
	broadcast  chan []byte
	register   chan *WSClient
	unregister chan *WSClient
}

// NewWSHub creates a new WebSocket hub.
func NewWSHub() *WSHub {
	return &WSHub{
		clients:    make(map[*WSClient]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *WSClient),
		unregister: make(chan *WSClient),
	}
}

// Run starts the hub event loop.
func (h *WSHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends a pipeline event to all connected WebSocket clients.
func (h *WSHub) Broadcast(event pipeline.Event) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	select {
	case h.broadcast <- data:
	default:
	}
}

func (s *Server) handleWSThreats(c *gin.Context) {
	tokenStr := c.Query("token")
	if tokenStr != "" {
		_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(s.config.Dashboard.SecretKey), nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[sentinel] WebSocket upgrade error: %v", err)
		return
	}

	client := &WSClient{conn: conn, send: make(chan []byte, 256), hub: s.wsHub, filter: "threats"}
	s.wsHub.register <- client
	go client.writePump()
	go client.readPump()
}

func (s *Server) handleWSMetrics(c *gin.Context) {
	tokenStr := c.Query("token")
	if tokenStr != "" {
		_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(s.config.Dashboard.SecretKey), nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[sentinel] WebSocket upgrade error: %v", err)
		return
	}

	client := &WSClient{conn: conn, send: make(chan []byte, 256), hub: s.wsHub, filter: "metrics"}
	s.wsHub.register <- client
	go client.writePump()
	go client.readPump()
}

func (c *WSClient) writePump() {
	defer c.conn.Close()
	for message := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
			return
		}
	}
}

func (c *WSClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
