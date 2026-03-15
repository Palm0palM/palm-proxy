package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/natefinch/lumberjack.v2"
)

/* 协议头格式：
 * 1 byte:  地址类型 (0x01=IPv4, 0x03=域名, 0x04=IPv6)
 * 1 byte:  地址长度
 * N bytes: 地址
 * 2 bytes: 端口
 */

const (
	ExitCodeOk     = 0
	ExitCodeConfig = 11 + iota
	ExitCodeSocket
)

func main() {
	initLogger()

	err := godotenv.Load()
	if err != nil {
		slog.Error("读取配置文件.env失败", slog.String("err", err.Error()))
		os.Exit(ExitCodeConfig)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		slog.Error("建立监听端口失败", slog.String("err", err.Error()))
		os.Exit(ExitCodeSocket)
	}
	defer listener.Close()
	slog.Info("SOCKS5监听已启动", slog.String("addr", listener.Addr().String()))

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	start := time.Now()
	defer func() {
		conn.Close()

		elapsed := time.Since(start)
		ms := elapsed.Milliseconds()
		slog.Info("连接已断开",
			slog.String("client_addr", conn.RemoteAddr().String()),
			slog.Int("client_port", conn.RemoteAddr().(*net.TCPAddr).Port),
			slog.Int64("duration_ms", ms),
		)
	}()

	// 读取预交换密钥psk
	keyStr := os.Getenv("AEAD_KEY")
	if len(keyStr) != 32 {
		slog.Error("密钥字节数错误",
			slog.String("AEAD_KEY", keyStr),
			slog.Int("AEAD_KEY_LEN", len(keyStr)),
		)
		return
	}
	psk := []byte(keyStr)

	// 握手
	sessionAEAD, err := performHandshake(conn, psk)
	if err != nil {
		slog.Error("握手失败", slog.String("err", err.Error()))
		return
	}

	slog.Info("握手成功，连接已建立，等待客户端的转发请求")

	// 计数器
	var recvCounter uint64 = 0
	var sendCounter uint64 = 0

	// 读取并解密第一个帧
	headerPayload, err := readEncryptedFrame(conn, sessionAEAD, &recvCounter)
	if err != nil {
		slog.Error("协议头读取失败", slog.String("err", err.Error()))
		return
	}

	// 解析协议头，提取信息
	if len(headerPayload) < 4 {
		slog.Error("协议头过短", slog.Int("header_length", len(headerPayload)))
		return
	}
	addrLen := int(headerPayload[1])
	addrStr := string(headerPayload[2 : 2+addrLen])
	portBuf := headerPayload[2+addrLen : 2+addrLen+2]
	port := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(addrStr, strconv.Itoa(int(port)))
	slog.Info("收到转发请求", slog.String("targetAddr", targetAddr))

	// 代替客户端发起连接
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		slog.Error("连接目标失败", slog.String("err", err.Error()))
		return
	}
	defer target.Close()

	// 双工加密转发管道
	// errChan是断开连接的信号
	errChan := make(chan error, 2)

	// 从目标处读取帧，转发给客户端
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

	// 从客户端读取帧，转发给目标地址
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

	<-errChan
}

// 用于生成Nonce, counter放入第5-8字节
func generateNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// 读取并解密加密的帧
func readEncryptedFrame(reader io.Reader, aead cipher.AEAD, counter *uint64) ([]byte, error) {
	// 先接收长度报文
	lenBuf := make([]byte, 18)
	if _, err := io.ReadFull(reader, lenBuf); err != nil {
		slog.Warn("读取到的长度报文过短", slog.String("err", err.Error()))
		return nil, err
	}

	// 生成Nonce
	nonceLen := generateNonce(*counter)
	*counter++

	plainLenBuf, err := aead.Open(nil, nonceLen, lenBuf, nil)
	if err != nil {
		slog.Error("头部解密失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("头部解密失败，可能被探测或篡改: %v", err)
	}
	payloadLen := binary.BigEndian.Uint16(plainLenBuf)

	// 读取加密的数据负载
	payloadBuf := make([]byte, payloadLen+16)
	if _, err := io.ReadFull(reader, payloadBuf); err != nil {
		slog.Error("读取正文失败", slog.String("err", err.Error()))
		return nil, err
	}
	slog.Info("完成一轮读取+解密", slog.Int("payload_len", len(payloadBuf)))

	noncePayload := generateNonce(*counter)
	*counter++

	plainPayload, err := aead.Open(nil, noncePayload, payloadBuf, nil)
	if err != nil {
		slog.Error("数据解密失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("数据解密失败: %v", err)
	}

	return plainPayload, nil
}

// 加密并发送读取的帧
func writeEncryptedFrame(writer io.Writer, aead cipher.AEAD, counter *uint64, payload []byte) error {
	const maxPayloadSize = 16384 // 最大 Chunk 大小限制 (16KB)

	for len(payload) > 0 {
		chunkSize := len(payload)
		if chunkSize > maxPayloadSize {
			chunkSize = maxPayloadSize
		}

		// chunk提取出需要处理的一部分，然后将payload向后移动
		chunk := payload[:chunkSize]
		payload = payload[chunkSize:]

		// 加密并发送长度头部
		plainLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(plainLenBuf, uint16(chunkSize))

		nonceLen := generateNonce(*counter)
		*counter++

		encLen := aead.Seal(nil, nonceLen, plainLenBuf, nil)

		if _, err := writer.Write(encLen); err != nil {
			slog.Error("长度头部写入失败", slog.String("err", err.Error()))
			return err
		}

		// 加密并发送数据负载
		noncePayload := generateNonce(*counter)
		*counter++
		encPayload := aead.Seal(nil, noncePayload, chunk, nil)

		if _, err := writer.Write(encPayload); err != nil {
			slog.Error("正文负载写入失败", slog.String("err", err.Error()))
			return err
		}
		slog.Info("完成一轮负载写入", slog.Int("payload_len", len(payload)))
	}
	return nil
}

// 握手操作 交换密钥
func performHandshake(conn net.Conn, psk []byte) (cipher.AEAD, error) {
	pskAEAD, err := chacha20poly1305.New(psk)
	if err != nil {
		slog.Error("基于psk的密钥生成失败", slog.String("err", err.Error()))
		return nil, err
	}

	var recvCounter uint64 = 0
	var sendCounter uint64 = 0

	// 读取收到的公钥
	clientPubKey, err := readEncryptedFrame(conn, pskAEAD, &recvCounter)
	if err != nil {
		slog.Error("读取客户端公钥失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("读取客户端公钥失败: %v", err)
	}
	if len(clientPubKey) != 32 {
		slog.Error("客户端公钥长度非法", slog.Int("len", len(clientPubKey)))
		return nil, fmt.Errorf("非法客户端公钥长度")
	}

	// 生成临时私钥
	var myPrivateKey [32]byte
	if _, err := io.ReadFull(rand.Reader, myPrivateKey[:]); err != nil {
		slog.Error("生成临时私钥失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("生成服务端私钥失败: %v", err)
	}

	myPublicKey, err := curve25519.X25519(myPrivateKey[:], curve25519.Basepoint)
	if err != nil {
		slog.Error("计算公钥失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("计算服务端公钥失败: %v", err)
	}

	if err := writeEncryptedFrame(conn, pskAEAD, &sendCounter, myPublicKey); err != nil {
		slog.Error("发送公钥失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("发送服务端公钥失败: %v", err)
	}

	sharedSecret, err := curve25519.X25519(myPrivateKey[:], clientPubKey)
	if err != nil {
		slog.Error("计算SharedSecret失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("计算 Shared Secret 失败: %v", err)
	}

	info := []byte("palm-proxy-handshake-phase")
	hkdfReader := hkdf.New(sha256.New, sharedSecret, psk, info)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		slog.Error("HKDF派生失败", slog.String("err", err.Error()))
		return nil, fmt.Errorf("HKDF 派生密钥失败: %v", err)
	}

	return chacha20poly1305.New(sessionKey)
}

func initLogger() {
	fileWriter := &lumberjack.Logger{
		Filename:   "/var/log/vps_proxy.log", // 日志文件路径
		MaxSize:    50,                       // 每个文件最大 50 MB
		MaxBackups: 3,                        // 最多保留 3 个旧文件
		MaxAge:     28,                       // 最多保留 28 天
		Compress:   true,                     // 自动压缩旧文件
	}

	// 使用 slog 配置 JSON 格式和日志级别
	logger := slog.New(slog.NewJSONHandler(fileWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo, // 只记录 INFO 及以上级别
	}))

	// 设置为全局默认 Logger
	slog.SetDefault(logger)
}
