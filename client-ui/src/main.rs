use std::error::Error;
use std::env;
use std::path::Path;
use dotenvy::from_path;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() -> AppResult<()> {
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

async fn handle_connection(mut conn: TcpStream) -> AppResult<()> {
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
    let mut len: u8;

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
            len = host_len[0];

            let mut host = vec![0u8; len as usize];
            conn.read_exact(&mut host).await?;
            String::from_utf8_lossy(&host).into_owned()
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

    from_path(Path::new("../shared/.env"))?;
    let vps_addr = env::var("VPS_ADDR")?;

    // 连接VPS
    let mut target_conn = TcpStream::connect(&vps_addr).await?;
    
    /* 先发送协议头：
     * 1 byte: 地址类型 0x01 v4 0x02 domain 0x03 v6
     * 1 byte: 地址长度
     * len byte: 地址
     * 2 byte: 端口
     * n byte: 正文
     */
    let addr_bytes = addr.as_bytes();
    let mut header_buf = Vec::new();
    header_buf.push(atyp);
    header_buf.push(addr_bytes.len() as u8);
    header_buf.extend_from_slice(addr_bytes);
    header_buf.extend_from_slice(&port.to_be_bytes());

    // 发送协议头
    target_conn.write_all(&header_buf).await?;

    // 建立双向数据通道
    let (mut client_read, mut client_write) = tokio::io::split(&mut conn);
    let (mut target_read, mut target_write) = tokio::io::split(&mut target_conn);

    let client_to_target = async {
        tokio::io::copy(&mut client_read, &mut target_write).await?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };

    let target_to_client = async {
        tokio::io::copy(&mut target_read, &mut client_write).await?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };

    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}


