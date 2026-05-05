// server.go - روی سرور المان اجرا کن
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "encoding/binary"
    "fmt"
    "io"
    "log"
    "net"
    "time"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/hkdf"
)

const (
    SERVER_PORT = ":8443"      // پورت تونل
    XUI_PORT    = "127.0.0.1:443" // پورت XUI panel
    BUFFER_SIZE = 32768
    PSK         = "d5f9a2c18e4b7063d91f2a8c4e5b60721d3f4a9b8e7c6d5a1f0e2b3c4d5a6b7e" // حتما عوض کن!
)

type SecureTunnel struct {
    aead   cipher.AEAD
    conn   net.Conn
    nonce  []byte
    counter uint64
}

func deriveKey(password string, salt []byte) []byte {
    hash := sha256.New
    hkdf := hkdf.New(hash, []byte(password), salt, []byte("quantum-tunnel-v1"))
    key := make([]byte, chacha20poly1305.KeySize)
    if _, err := io.ReadFull(hkdf, key); err != nil {
        panic(err)
    }
    return key
}

func newSecureTunnel(conn net.Conn, key []byte) (*SecureTunnel, error) {
    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, aead.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    
    return &SecureTunnel{
        aead:    aead,
        conn:    conn,
        nonce:   nonce,
        counter: 0,
    }, nil
}

func (st *SecureTunnel) getNonce() []byte {
    nonce := make([]byte, st.aead.NonceSize())
    copy(nonce, st.nonce)
    binary.BigEndian.PutUint64(nonce[len(nonce)-8:], st.counter)
    st.counter++
    return nonce
}

func (st *SecureTunnel) encrypt(plaintext []byte) ([]byte, error) {
    // Add random padding
    padding := make([]byte, 16+rand.Intn(240))
    rand.Read(padding)
    
    data := append([]byte{byte(len(padding))}, padding...)
    data = append(data, plaintext...)
    
    nonce := st.getNonce()
    ciphertext := st.aead.Seal(nil, nonce, data, nil)
    
    // Prepend length
    result := make([]byte, 4+len(nonce)+len(ciphertext))
    binary.BigEndian.PutUint32(result[0:4], uint32(len(nonce)+len(ciphertext)))
    copy(result[4:], nonce)
    copy(result[4+len(nonce):], ciphertext)
    
    return result, nil
}

func (st *SecureTunnel) decrypt(data []byte) ([]byte, error) {
    if len(data) < st.aead.NonceSize()+st.aead.Overhead() {
        return nil, fmt.Errorf("data too short")
    }
    
    nonce := data[:st.aead.NonceSize()]
    ciphertext := data[st.aead.NonceSize():]
    
    plaintext, err := st.aead.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }
    
    // Remove padding
    if len(plaintext) < 1 {
        return nil, fmt.Errorf("invalid padding")
    }
    paddingLen := int(plaintext[0])
    if len(plaintext) < 1+paddingLen {
        return nil, fmt.Errorf("invalid padding length")
    }
    
    return plaintext[1+paddingLen:], nil
}

func (st *SecureTunnel) readFrame() ([]byte, error) {
    // Read length
    lenBuf := make([]byte, 4)
    if _, err := io.ReadFull(st.conn, lenBuf); err != nil {
        return nil, err
    }
    
    length := binary.BigEndian.Uint32(lenBuf)
    if length > BUFFER_SIZE*2 {
        return nil, fmt.Errorf("frame too large")
    }
    
    // Read frame
    frame := make([]byte, length)
    if _, err := io.ReadFull(st.conn, frame); err != nil {
        return nil, err
    }
    
    return st.decrypt(frame)
}

func (st *SecureTunnel) writeFrame(data []byte) error {
    encrypted, err := st.encrypt(data)
    if err != nil {
        return err
    }
    
    _, err = st.conn.Write(encrypted)
    return err
}

func handleClient(clientConn net.Conn) {
    defer clientConn.Close()
    
    log.Printf("New connection from %s", clientConn.RemoteAddr())
    
    // Handshake
    salt := make([]byte, 32)
    if _, err := io.ReadFull(clientConn, salt); err != nil {
        log.Printf("Handshake failed: %v", err)
        return
    }
    
    key := deriveKey(PSK, salt)
    tunnel, err := newSecureTunnel(clientConn, key)
    if err != nil {
        log.Printf("Tunnel creation failed: %v", err)
        return
    }
    
    // Send nonce
    if _, err := clientConn.Write(tunnel.nonce); err != nil {
        log.Printf("Nonce send failed: %v", err)
        return
    }
    
    // Connect to XUI
    xuiConn, err := net.DialTimeout("tcp", XUI_PORT, 10*time.Second)
    if err != nil {
        log.Printf("XUI connection failed: %v", err)
        return
    }
    defer xuiConn.Close()
    
    log.Printf("Connected to XUI panel")
    
    // Bidirectional relay
    done := make(chan bool, 2)
    
    // Client -> XUI
    go func() {
        defer func() { done <- true }()
        for {
            data, err := tunnel.readFrame()
            if err != nil {
                return
            }
            if _, err := xuiConn.Write(data); err != nil {
                return
            }
        }
    }()
    
    // XUI -> Client
    go func() {
        defer func() { done <- true }()
        buf := make([]byte, BUFFER_SIZE)
        for {
            n, err := xuiConn.Read(buf)
            if err != nil {
                return
            }
            if err := tunnel.writeFrame(buf[:n]); err != nil {
                return
            }
        }
    }()
    
    <-done
    log.Printf("Connection closed: %s", clientConn.RemoteAddr())
}

func main() {
    // Generate self-signed certificate
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatal("Certificate load failed. Generate with:\n" +
            "openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=example.com'")
    }
    
    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_CHACHA20_POLY1305_SHA256,
            tls.TLS_AES_256_GCM_SHA384,
        },
    }
    
    listener, err := tls.Listen("tcp", SERVER_PORT, config)
    if err != nil {
        log.Fatalf("Listen failed: %v", err)
    }
    defer listener.Close()
    
    log.Printf("🔒 Quantum Tunnel Server listening on %s", SERVER_PORT)
    log.Printf("📡 Forwarding to XUI panel at %s", XUI_PORT)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Accept error: %v", err)
            continue
        }
        go handleClient(conn)
    }
}
