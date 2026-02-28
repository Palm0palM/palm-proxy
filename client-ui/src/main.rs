use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 监听本地端口
    let listener = TcpListener::bind("127.0.0.1:1080").await?;
    println!("SOCKS5 代理已启动，监听在 127.0.0.1:1080...");

    loop {
        let (conn, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn).await {
                eprintln!("处理连接时出错: {}", e);
            }
        });
    }
}

async fn handle_connection(mut conn: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 2];
    conn.read_exact(&mut buf).await?;

    let version = buf[0];
    let nmethods = buf[1] as usize;

    if version != 0x05 {
        return Err(format!("不支持的协议版本: 0x{:02x}", version).into());
    }

    let mut methods = vec![0u8; nmethods];
    conn.read_exact(&mut methods).await?;

    println!("收到新的 SOCKS5 连接，支持 {} 种认证方法: {:?}", nmethods, methods);

    conn.write_all(&[0x05, 0x00]).await?;

    let mut header = [0u8; 4];
    conn.read_exact(&mut header).await?;

    let ver = header[0];
    let cmd = header[1];
    let atyp = header[3];

    // 版本号必须是 0x05，且命令必须是 0x01 (CONNECT)
    if ver != 0x05 || cmd != 0x01 {
        return Err("不支持的协议版本或命令".into());
    }

    // 解析目标地址
    let addr: String = match atyp {
        0x01 => {
            // IPv4 地址 (4字节)
            let mut ipv4 = [0u8; 4];
            conn.read_exact(&mut ipv4).await?;
            Ipv4Addr::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3]).to_string()
        }
        0x03 => {
            // 域名 会调用DNS查询
            let mut host_len = [0u8; 1];
            conn.read_exact(&mut host_len).await?;
            let len = host_len[0] as usize;

            let mut host = vec![0u8; len];
            conn.read_exact(&mut host).await?;
            let domain = String::from_utf8_lossy(&host).into_owned();
            let mut addrs = tokio::net::lookup_host(format!("{}:0", domain)).await?;

            let addr = addrs.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "解析成功，但没有返回任何 IP")
            })?;

            addr.ip().to_string()
        }
        0x04 => {
            // IPv6 地址 (16字节)
            let mut ipv6 = [0u8; 16];
            conn.read_exact(&mut ipv6).await?;
            Ipv6Addr::from(ipv6).to_string()
        }
        _ => {
            return Err(format!("不支持的地址类型: 0x{:02x}", atyp).into());
        }
    };

    // 读取 2 字节的目标端口 (大端序)
    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    let dest_addr = format!("{}:{}", addr, port);
    println!("成功解析！客户端想要访问: {}", dest_addr);

    // 回复客户端：连接成功，代理绑定地址全为0
    let reply = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    conn.write_all(&reply).await?;

    // 代理服务端建立与目标地址的真实 TCP 连接
    let mut target_conn = TcpStream::connect(&dest_addr).await?;
    println!("成功连接到目标网站: {}，开始双向转发数据...", dest_addr);

    // 建立双向数据通道
    tokio::io::copy_bidirectional(&mut conn, &mut target_conn).await?;

    Ok(())
}