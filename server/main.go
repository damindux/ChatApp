package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	SharedSecret []byte `json:"-"`
}

type Message struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
}

var db *sql.DB
var clients = make(map[string]*websocket.Conn)
var sharedSecrets = make(map[string][]byte)

func main() {
	// Open SQLite database
	var err error
	db, err = sql.Open("sqlite3", "./chat.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create users table if not exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        password TEXT
                    )`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        message TEXT NOT NULL,
		old_shared_secret BLOB NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
	if err != nil {
		log.Fatal(err)
	}

	// Handle HTTP routes
	http.HandleFunc("/signup", handleSignUp)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/users", handleUsers)
	http.HandleFunc("/chat", handleChat)
	http.HandleFunc("/messages", handleMessages)
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/ws", handleWS)

	// Start HTTP server
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	// Ensure the method is GET as we are reading data
	if r.Method != http.MethodGet {
		http.Error(w, "Method is not supported.", http.StatusMethodNotAllowed)
		return
	}

	// Get all users
	rows, err := db.Query("SELECT username FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []string // Slice to hold usernames

	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, username)
	}

	// Check for errors encountered during iteration
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert the usernames slice to JSON
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword := hashPassword(user.Password)

	// Insert user into database
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with a success message and status code 201
	response := map[string]string{"message": "Registration successful!"}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if user exists
	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username=?", user.Username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Check if password is correct
	if hashPassword(user.Password) != storedPassword {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Send a successful login JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../client/index.html")
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../client/chat.html")
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
	if err != nil {
		http.Error(w, "Could not upgrade to WebSocket", http.StatusBadRequest)
		return
	}
	defer conn.Close()

	var user User
	var clientPublicKey string

	// Read the first message, which should contain the username and public key for authentication
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Println("Error reading from WebSocket:", err)
		return
	}

	var authMsg map[string]string
	if err := json.Unmarshal(message, &authMsg); err != nil {
		log.Println("Error decoding JSON message:", err)
		return
	}

	if authMsg["type"] == "auth" {
		user.Username = authMsg["username"]
		clientPublicKey = authMsg["publicKey"]
		if user.Username == "" || clientPublicKey == "" {
			log.Println("Authentication failed: Username or public key is empty.")
			return
		}

		// Generate server's ECC key pair
		serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Println("Error generating server's ECC key pair:", err)
			return
		}
		serverPublicKey := serverKey.PublicKey

		// Derive shared secret using client's public key
		clientPubKey, err := hex.DecodeString(clientPublicKey)
		if err != nil {
			log.Println("Error decoding client's public key:", err)
			return
		}

		x, y := elliptic.Unmarshal(elliptic.P256(), clientPubKey)
		clientPublicKeyEC := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		sharedSecretX, _ := serverKey.PublicKey.ScalarMult(clientPublicKeyEC.X, clientPublicKeyEC.Y, serverKey.D.Bytes())

		sharedSecret := sha1.Sum(sharedSecretX.Bytes())
		user.SharedSecret = sharedSecret[:8] // Use the first 8 bytes for DES key

		// Store shared secret in the global map
		sharedSecrets[user.Username] = user.SharedSecret

		// Send server's public key to client
		serverPubKeyBytes := elliptic.Marshal(elliptic.P256(), serverPublicKey.X, serverPublicKey.Y)
		err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type": "keyExchange", "serverPublicKey": "`+hex.EncodeToString(serverPubKeyBytes)+`"}`))
		if err != nil {
			log.Println("Error sending server's public key:", err)
			return
		}

		clients[user.Username] = conn
		log.Printf("User %s authenticated and connected via WebSocket.\n", user.Username)
	} else {
		log.Println("First message must be authentication.")
		return
	}

	// Main loop for reading messages
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading from WebSocket for user %s: %v", user.Username, err)
			delete(clients, user.Username)
			delete(sharedSecrets, user.Username) // Clean up the shared secret
			return
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Println("Error decoding JSON message:", err)
			continue
		}

		handleChatMessage(user.Username, msg, user.SharedSecret)
	}
}

func handleChatMessage(username string, msg Message, sharedSecret []byte) {
	// Encrypt the message content
	encryptedContent, err := encryptDES(msg.Content, sharedSecret)
	if err != nil {
		log.Printf("Error encrypting message content from %s to %s: %v\n", username, msg.Recipient, err)
		return
	}

	// Store message in the database
	_, err = db.Exec("INSERT INTO messages (sender, recipient, message, old_shared_secret) VALUES (?, ?, ?, ?)", username, msg.Recipient, encryptedContent, sharedSecret)
	if err != nil {
		log.Printf("Error storing message from %s to %s: %v\n", username, msg.Recipient, err)
		return
	}

	// Send message to recipient if they are online
	if recipientConn, ok := clients[msg.Recipient]; ok {
		msg.Content, err = decryptDES(encryptedContent, sharedSecret)
		if err != nil {
			log.Printf("Error decrypting the message to %s: %v", msg.Recipient, err)
		}

		// Create a map to add the type field
		messageWithType := map[string]interface{}{
			"type":      "message",
			"sender":    msg.Sender,
			"recipient": msg.Recipient,
			"content":   msg.Content,
			"timestamp": time.Now().Format("2006-01-02 15:04:05"),
		}

		errr := recipientConn.WriteJSON(messageWithType)
		if errr != nil {
			log.Printf("Error forwarding message to %s: %v", msg.Recipient, err)
		}
	} else {
		log.Printf("Recipient '%s' not online; message stored for later retrieval\n", msg.Recipient)
	}
}

// encryptDES encrypts the plaintext using DES encryption in CBC mode with PKCS#7 padding.
func encryptDES(plainText string, key []byte) (string, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	plainTextBytes := []byte(plainText)
	paddingSize := des.BlockSize - len(plainTextBytes)%des.BlockSize
	paddedText := append(plainTextBytes, bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)...)

	ciphertext := make([]byte, des.BlockSize+len(paddedText))
	iv := ciphertext[:des.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[des.BlockSize:], paddedText)

	return hex.EncodeToString(ciphertext), nil
}

// decryptDES decrypts the ciphertext using DES decryption in CBC mode with PKCS#7 padding.
func decryptDES(cipherTextHex string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return "", err
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < des.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:des.BlockSize]
	ciphertext = ciphertext[des.BlockSize:]

	if len(ciphertext)%des.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	// Create a new CBC decrypter and decrypt the ciphertext
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Remove the padding to get the original plaintext
	paddingSize := int(decrypted[len(decrypted)-1])
	if paddingSize > des.BlockSize || paddingSize <= 0 {
		log.Printf("decrypted size: %v, Padding: %v", len(decrypted), paddingSize)
		return "", errors.New("invalid padding size")
	}

	// Ensure that the padding size is not larger than the decrypted message length
	if len(decrypted) < paddingSize {
		return "", errors.New("padding size is larger than decrypted message length")
	}

	return string(decrypted[:len(decrypted)-paddingSize]), nil
}

func handleMessages(w http.ResponseWriter, r *http.Request) {
	// Ensure the request is a GET request
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the username from the URL query parameters
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Fetch messages from the database
	messages, err := getMessagesForUser(username)
	if err != nil {
		log.Printf("Failed to retrieve messages: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/json")

	// Encode the messages to JSON and send the response
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(messages); err != nil {
		log.Printf("Failed to encode messages: %v", err)
		http.Error(w, "Error encoding messages", http.StatusInternalServerError)
	}
}

func getMessagesForUser(username string) ([]Message, error) {
	rows, err := db.Query("SELECT sender, message, old_shared_secret, datetime(timestamp, 'localtime') FROM messages WHERE recipient = ? ORDER BY timestamp ASC", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var sharedSecret []byte
		err := rows.Scan(&msg.Sender, &msg.Content, &sharedSecret, &msg.Timestamp)
		if err != nil {
			return nil, err
		}

		decryptedContent, err := decryptDES(msg.Content, sharedSecret)
		if err != nil {
			log.Printf("Error decrypting message for recipient %s: %v", msg.Recipient, err)
			continue // Skip this message if decryption fails
		}
		msg.Content = decryptedContent

		messages = append(messages, msg)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

func hashPassword(password string) string {
	hasher := sha1.New()
	hasher.Write([]byte(password))
	sha1Hash := hex.EncodeToString(hasher.Sum(nil))
	return sha1Hash
}
