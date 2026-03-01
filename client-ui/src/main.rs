use std::error::Error;
use std::env;
use std::path::Path;
use dotenvy::from_path;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf, tcp::OwnedReadHalf};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

// 发送时，每个 Chunk 最大明文大小为16KB
const MAX_PAYLOAD_SIZE: usize = 16384;

#[tokio::main]
async fn main() -> AppResult<()> {
    from_path(Path::new("../shared/.env"))?;

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
    let len: u8;

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

    // 建立双向数据通道
    let (mut client_read, mut client_write) = conn.into_split();
    let (mut target_read, mut target_write) = target_conn.into_split();

    // 初始化计数器 每个新的 TCP 连接从 0 开始
    let mut send_counter: u64 = 0;
    let mut receive_counter: u64 = 0;

    // 从密码字节数组生成 Key
    let aead_key = env::var("AEAD_KEY")?;
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, aead_key.as_bytes()).unwrap();
    let less_safe_key = LessSafeKey::new(unbound_key);

    // 发送协议头
    write_encrypted_frame(&mut target_write, &less_safe_key, &mut send_counter, &header_buf).await?;

    let client_to_target = async {
        let mut buf = [0u8; 8192]; // 从本地 SOCKS5 客户端读取的缓冲区
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let data_slice = &buf[..n];
                    write_encrypted_frame(&mut target_write, &less_safe_key, &mut send_counter, data_slice).await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };

    let target_to_client = async {
        loop {
            match read_encrypted_frame_and_forward(&mut target_read, &less_safe_key, &mut receive_counter, &mut client_write).await {
                Ok(true) => continue, // 成功读取一帧，继续等下一帧
                Ok(false) => break,   // 正常收到 EOF，退出循环
                Err(e) => return Err(e),
            }
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };

    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

fn generate_nonce_from_counter(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}

async fn write_encrypted_frame(
    writer: &mut OwnedWriteHalf,
    key: &LessSafeKey,
    counter: &mut u64,
    payload: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for chunk in payload.chunks(MAX_PAYLOAD_SIZE) {
        let chunk_len = chunk.len() as u16;

        // 加密并发送长度头部 (18 bytes)
        let mut len_buf = chunk_len.to_be_bytes().to_vec();
        let nonce_len = generate_nonce_from_counter(*counter);
        *counter += 1;

        key.seal_in_place_append_tag(nonce_len, Aad::empty(), &mut len_buf)
            .map_err(|_| "长度头部加密失败")?;
        writer.write_all(&len_buf).await?;

        // 加密并发送实际数据块
        let mut payload_buf = chunk.to_vec();
        let nonce_payload = generate_nonce_from_counter(*counter);
        *counter += 1;

        key.seal_in_place_append_tag(nonce_payload, Aad::empty(), &mut payload_buf)
            .map_err(|_| "数据负载加密失败")?;
        writer.write_all(&payload_buf).await?;
    }

    Ok(())
}
async fn read_encrypted_frame_and_forward(
    reader: &mut OwnedReadHalf,
    key: &LessSafeKey,
    counter: &mut u64,
    client_writer: &mut OwnedWriteHalf,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let mut len_buf = [0u8; 18];

    // 如果刚准备读取下一个帧的长度时就遇到了 EOF，说明对方正常关闭了连接
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {},
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(e) => return Err(e.into()),
    }

    let nonce_len = generate_nonce_from_counter(*counter);
    *counter += 1;

    let plain_text = key.open_in_place(nonce_len, Aad::empty(), &mut len_buf)
        .map_err(|_| "头部 AEAD 解密失败")?;

    let payload_len = u16::from_be_bytes(plain_text[..2].try_into().unwrap());

    let mut payload_buf = vec![0u8; (payload_len + 16) as usize];
    reader.read_exact(&mut payload_buf).await?;

    let nonce_payload = generate_nonce_from_counter(*counter);
    *counter += 1;

    let real_payload = key.open_in_place(nonce_payload, Aad::empty(), &mut payload_buf)
        .map_err(|_| "负载 AEAD 解密失败")?;

    client_writer.write_all(real_payload).await?;

    Ok(true) // 返回 true 表示成功处理了一个帧，可以继续循环
}


