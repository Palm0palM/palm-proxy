use std::error::Error;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf, tcp::OwnedReadHalf};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::SystemRandom;
use ring::agreement;
use ring::{hkdf, hkdf::Okm};
use dotenvy;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

// 发送时，每个 Chunk 最大明文大小为16KB
const MAX_PAYLOAD_SIZE: usize = 16384;

// 用于 HKDF expand 的自定义类型，指定输出密钥长度为 32 字节
struct HkdfOutputLen(usize);

impl hkdf::KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenvy::dotenv().ok();

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

    // 回复客户端：选择无认证方式
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
            // 域名，会调用 DNS 查询
            let mut host_len_buf = [0u8; 1];
            conn.read_exact(&mut host_len_buf).await?;
            let host_len = host_len_buf[0] as usize;

            let mut host = vec![0u8; host_len];
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

    // 回复客户端：连接成功，代理绑定地址全为 0
    let reply = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    conn.write_all(&reply).await?;

    let vps_addr = env::var("VPS_ADDR")?;
    let target_conn = TcpStream::connect(&vps_addr).await?;

    let (mut target_read, mut target_write) = target_conn.into_split();

    // 从环境变量读取 32 字节 PSK
    let psk_raw = env::var("AEAD_KEY")?;
    let psk_bytes = {
        let mut arr = [0u8; 32];
        let src = psk_raw.as_bytes();
        let copy_len = src.len().min(32);
        arr[..copy_len].copy_from_slice(&src[..copy_len]);
        arr
    };

    let less_safe_key = perform_handshake(&mut target_write, &mut target_read, &psk_bytes).await?;
    println!("握手完成，开始使用 Session Key 转发数据...");

    /* 协议头格式：
     * 1 byte:  地址类型 (0x01=IPv4, 0x03=域名, 0x04=IPv6)
     * 1 byte:  地址长度
     * N bytes: 地址
     * 2 bytes: 端口 (大端序)
     */
    let addr_bytes = addr.as_bytes();
    let mut header_buf = Vec::new();
    header_buf.push(atyp);
    header_buf.push(addr_bytes.len() as u8);
    header_buf.extend_from_slice(addr_bytes);
    header_buf.extend_from_slice(&port.to_be_bytes());

    // 建立双向数据通道
    let (mut client_read, mut client_write) = conn.into_split();

    // 初始化计数器，每个新的 TCP 连接从 0 开始
    let mut send_counter: u64 = 0;
    let mut receive_counter: u64 = 0;

    // 发送协议头（使用 Session Key 加密）
    write_encrypted_frame(&mut target_write, &less_safe_key, &mut send_counter, &header_buf).await?;

    let client_to_target = async {
        let mut buf = [0u8; 8192];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    write_encrypted_frame(
                        &mut target_write,
                        &less_safe_key,
                        &mut send_counter,
                        &buf[..n],
                    ).await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };

    let target_to_client = async {
        loop {
            match read_encrypted_frame_and_forward(
                &mut target_read,
                &less_safe_key,
                &mut receive_counter,
                &mut client_write,
            ).await {
                Ok(true)  => continue, // 成功读取一帧，继续等下一帧
                Ok(false) => break,    // 正常收到 EOF，退出循环
                Err(e)    => return Err(e),
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

        // 加密并发送长度头部（2字节明文 + 16字节 tag = 18字节密文）
        let mut len_buf = chunk_len.to_be_bytes().to_vec();
        let nonce_len = generate_nonce_from_counter(*counter);
        *counter += 1;
        key.seal_in_place_append_tag(nonce_len, Aad::empty(), &mut len_buf)
            .map_err(|_| "长度头部加密失败")?;
        writer.write_all(&len_buf).await?;

        // 加密并发送实际数据块（N字节明文 + 16字节 tag）
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
    // 读取 18 字节密文长度头部（2字节明文 + 16字节 tag）
    let mut len_buf = [0u8; 18];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(e) => return Err(e.into()),
    }

    let nonce_len = generate_nonce_from_counter(*counter);
    *counter += 1;
    let plain_text = key
        .open_in_place(nonce_len, Aad::empty(), &mut len_buf)
        .map_err(|_| "头部 AEAD 解密失败")?;

    let payload_len = u16::from_be_bytes(plain_text[..2].try_into().unwrap());

    // 读取 payload_len + 16 字节密文数据
    let mut payload_buf = vec![0u8; payload_len as usize + 16];
    reader.read_exact(&mut payload_buf).await?;

    let nonce_payload = generate_nonce_from_counter(*counter);
    *counter += 1;
    let real_payload = key
        .open_in_place(nonce_payload, Aad::empty(), &mut payload_buf)
        .map_err(|_| "负载 AEAD 解密失败")?;

    client_writer.write_all(real_payload).await?;

    Ok(true)
}

async fn read_encrypted_frame(
    reader: &mut OwnedReadHalf,
    key: &LessSafeKey,
    counter: &mut u64,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut len_buf = [0u8; 18];
    reader.read_exact(&mut len_buf).await?;

    let nonce_len = generate_nonce_from_counter(*counter);
    *counter += 1;
    let plain_text = key
        .open_in_place(nonce_len, Aad::empty(), &mut len_buf)
        .map_err(|_| "握手阶段 长度头部解密失败")?;

    let payload_len = u16::from_be_bytes(plain_text[..2].try_into().unwrap());

    let mut payload_buf = vec![0u8; payload_len as usize + 16];
    reader.read_exact(&mut payload_buf).await?;

    let nonce_payload = generate_nonce_from_counter(*counter);
    *counter += 1;
    let real_payload = key
        .open_in_place(nonce_payload, Aad::empty(), &mut payload_buf)
        .map_err(|_| "握手阶段 数据负载解密失败")?;

    Ok(real_payload.to_vec())
}

async fn perform_handshake(
    writer: &mut OwnedWriteHalf,
    reader: &mut OwnedReadHalf,
    psk_bytes: &[u8; 32],
) -> Result<LessSafeKey, Box<dyn Error + Send + Sync>> {
    let psk_unbound = UnboundKey::new(&CHACHA20_POLY1305, psk_bytes)
        .map_err(|_| "PSK 密钥初始化失败")?;
    let psk_key = LessSafeKey::new(psk_unbound);
    let mut handshake_send_counter: u64 = 0;
    let mut handshake_recv_counter: u64 = 0;
    
    let rng = SystemRandom::new();
    let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| "生成 X25519 私钥失败")?;
    let my_public_key = my_private_key
        .compute_public_key()
        .map_err(|_| "计算 X25519 公钥失败")?;
    
    write_encrypted_frame(writer, &psk_key, &mut handshake_send_counter, my_public_key.as_ref()).await?;
    
    let server_pub_key_bytes = read_encrypted_frame(reader, &psk_key, &mut handshake_recv_counter).await?;

    if server_pub_key_bytes.len() != 32 {
        return Err(format!("服务端返回的公钥长度错误，需要 32 字节，实际为 {} 字节", server_pub_key_bytes.len()).into());
    }

    let server_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, server_pub_key_bytes);

    let session_key_bytes: [u8; 32] = agreement::agree_ephemeral(
        my_private_key, &server_public_key,
        |key_material: &[u8]| -> Result<[u8; 32], ring::error::Unspecified> {
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, psk_bytes);
            let prk = salt.extract(key_material);

            let info: &[&[u8]] = &[b"palm-proxy-handshake-phase"];
            let okm: Okm<HkdfOutputLen> = prk
                .expand(info, HkdfOutputLen(32))?;

            let mut derived_key = [0u8; 32];
            okm.fill(&mut derived_key)?;

            Ok(derived_key)
        },
    ).flatten().map_err(|_| "ECDH 密钥协商与 HKDF 派生失败")?;

    let final_unbound = UnboundKey::new(&CHACHA20_POLY1305, &session_key_bytes)
        .map_err(|_| "Session Key 初始化失败")?;
    Ok(LessSafeKey::new(final_unbound))
}