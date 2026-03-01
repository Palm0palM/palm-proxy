package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("8080端口监听失败: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接收连接失败：%v", err)
			continue
		}

		go handleConnection(conn)
	}
}

/* 标准：
 * 1 byte: 地址类型 0x01 v4 0x02 domain 0x03 v6
 * 1 byte: 地址长度
 * len byte: 地址
 * 2 byte: 端口
 * n byte: 正文
 */

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 读取地址类型和长度
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	addrLen := buf[1]

	// 读取目标地址（IP 或域名）
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(conn, addrBuf); err != nil {
		return
	}
	targetAddrStr := string(addrBuf)

	// 读取目标端口
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// 拼接目标地址字符串 (无需手动执行 DNS 查询逻辑)
	target_addr := net.JoinHostPort(targetAddrStr, strconv.Itoa(int(port)))

	// 连接目标网站
	target, err := net.Dial("tcp", target_addr)
	if err != nil {
		log.Printf("连接目标服务器 %s 失败: %v", target_addr, err)
		return
	}
	defer target.Close()

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(conn, target)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(target, conn)
		errChan <- err
	}()

	<-errChan
}
