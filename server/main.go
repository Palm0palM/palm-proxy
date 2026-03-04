package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("加载.env文件失败：%v", err)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		log.Fatalf("端口监听失败: %v", err)
	}
	defer listener.Close()
	log.Println("服务端已启动，等待客户端连接...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	keyStr := os.Getenv("AEAD_KEY")
	if len(keyStr) != 32 {
		log.Println("密钥长度错误，必须为 32 字节")
		return
	}
	psk := []byte(keyStr)

	sessionAEAD, err := performHandshake(conn, psk)
	if err != nil {
		log.Printf("握手失败: %v", err)
		return
	}

	log.Println("安全握手完成，已生成安全会话密钥！")

	var recvCounter uint64 = 0
	var sendCounter uint64 = 0

	// 读取并解密第一个帧
	headerPayload, err := readEncryptedFrame(conn, sessionAEAD, &recvCounter)
	if err != nil {
		// 如果解密失败，直接 Return 掐断连接
		log.Printf("读取协议头失败: %v", err)
		return
	}

	// 解析协议头
	if len(headerPayload) < 4 {
		return
	}

	addrLen := int(headerPayload[1])
	// 边界检查，防止恶意构造的头部导致索引越界 Panic
	if len(headerPayload) < 2+addrLen+2 {
		return
	}

	addrStr := string(headerPayload[2 : 2+addrLen])
	portBuf := headerPayload[2+addrLen : 2+addrLen+2]
	port := binary.BigEndian.Uint16(portBuf)

	targetAddr := net.JoinHostPort(addrStr, strconv.Itoa(int(port)))
	log.Printf("客户端请求访问: %s", targetAddr)

	// 代替客户端发起连接
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("连接目标失败: %v", err)
		return
	}
	defer target.Close()

	// 双工加密转发管道
	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := target.Read(buf)
			if n > 0 {
				if writeErr := writeEncryptedFrame(conn, sessionAEAD, &sendCounter, buf[:n]); writeErr != nil {
					errChan <- writeErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		for {
			plainPayload, err := readEncryptedFrame(conn, sessionAEAD, &recvCounter)
			if err != nil {
				errChan <- err
				return
			}
			if _, err := target.Write(plainPayload); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// 阻塞等待，任意一端断开，整个函数退出触发 defer 回收
	<-errChan
}

func generateNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	// 将计数器放入 Nonce 的后 8 个字节
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func readEncryptedFrame(reader io.Reader, aead cipher.AEAD, counter *uint64) ([]byte, error) {
	lenBuf := make([]byte, 18)
	if _, err := io.ReadFull(reader, lenBuf); err != nil {
		return nil, err // 此处返回 EOF 属于正常断开
	}

	nonceLen := generateNonce(*counter)
	*counter++

	plainLenBuf, err := aead.Open(nil, nonceLen, lenBuf, nil)
	if err != nil {
		return nil, fmt.Errorf("头部解密失败 (可能被探测或篡改): %v", err)
	}

	payloadLen := binary.BigEndian.Uint16(plainLenBuf)

	// 读取加密的数据负载
	payloadBuf := make([]byte, payloadLen+16)
	if _, err := io.ReadFull(reader, payloadBuf); err != nil {
		return nil, err
	}

	noncePayload := generateNonce(*counter)
	*counter++

	plainPayload, err := aead.Open(nil, noncePayload, payloadBuf, nil)
	if err != nil {
		return nil, fmt.Errorf("数据解密失败: %v", err)
	}

	return plainPayload, nil
}

func writeEncryptedFrame(writer io.Writer, aead cipher.AEAD, counter *uint64, payload []byte) error {
	const maxPayloadSize = 16384 // 最大 Chunk 大小限制 (16KB)

	for len(payload) > 0 {
		chunkSize := len(payload)
		if chunkSize > maxPayloadSize {
			chunkSize = maxPayloadSize
		}

		chunk := payload[:chunkSize]
		payload = payload[chunkSize:]

		// 加密并发送长度头部
		plainLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(plainLenBuf, uint16(chunkSize))

		nonceLen := generateNonce(*counter)
		*counter++

		encLen := aead.Seal(nil, nonceLen, plainLenBuf, nil)

		if _, err := writer.Write(encLen); err != nil {
			return err
		}

		// 加密并发送数据负载
		noncePayload := generateNonce(*counter)
		*counter++
		encPayload := aead.Seal(nil, noncePayload, chunk, nil)

		if _, err := writer.Write(encPayload); err != nil {
			return err
		}
	}
	return nil
}

func performHandshake(conn net.Conn, psk []byte) (cipher.AEAD, error) {
	pskAEAD, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, err
	}

	var recvCounter uint64 = 0
	var sendCounter uint64 = 0

	clientPubKey, err := readEncryptedFrame(conn, pskAEAD, &recvCounter)
	if err != nil {
		return nil, fmt.Errorf("读取客户端公钥失败: %v", err)
	}
	if len(clientPubKey) != 32 {
		return nil, fmt.Errorf("非法客户端公钥长度")
	}

	var myPrivateKey [32]byte
	if _, err := io.ReadFull(rand.Reader, myPrivateKey[:]); err != nil {
		return nil, fmt.Errorf("生成服务端私钥失败: %v", err)
	}

	myPublicKey, err := curve25519.X25519(myPrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("计算服务端公钥失败: %v", err)
	}

	if err := writeEncryptedFrame(conn, pskAEAD, &sendCounter, myPublicKey); err != nil {
		return nil, fmt.Errorf("发送服务端公钥失败: %v", err)
	}

	sharedSecret, err := curve25519.X25519(myPrivateKey[:], clientPubKey)
	if err != nil {
		return nil, fmt.Errorf("计算 Shared Secret 失败: %v", err)
	}

	info := []byte("palm-proxy-handshake-phase")
	hkdfReader := hkdf.New(sha256.New, sharedSecret, psk, info)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, fmt.Errorf("HKDF 派生密钥失败: %v", err)
	}

	return chacha20poly1305.New(sessionKey)
}
