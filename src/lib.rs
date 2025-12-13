extern crate core;

use clap::ArgAction;
use clap::Parser;
use colored::Colorize;
use jiff::Zoned;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use std::fmt::Display;
use std::io::{Write, stdout};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// 代理tcp请求到远端服务器, 观察请求和响应的流量
///
/// 本地(明文) <---> 远端(明文/tls)
///
/// 应用只代理流量, 不进行压缩/解压缩
///
/// 如果使用 http, 可以提供 `Accept-Encoding: identity` 禁用压缩.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about)]
pub struct Args {
    /// 本地监听地址
    #[arg(short, long, default_value_t = String::from("0.0.0.0:8678"))]
    listen_addr: String,

    /// 远端服务器, ip:port
    #[arg(short, long)]
    remote_target: String,

    /// 远端服务器是否使用tls
    #[arg(long, default_value_t = false)]
    remote_tls: bool,

    /// 控制台不输出内容
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// 是否显示bytes数据
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    bytes_data: bool,

    /// 是否使用hex输出
    #[arg(long, default_value_t = false)]
    hex: bool,

    /// hex显示使用的行宽
    #[arg(long, default_value_t = 32)]
    hex_line: usize,
}

#[derive(Clone)]
struct Context {
    args: Args,
    req_id: u64,
}

impl Context {
    fn new(args: Args, req_id: u64) -> Self {
        Self { args, req_id }
    }
}

pub async fn cli_run(args: Args) -> CliResult {
    let server_addr: SocketAddr = args.listen_addr.parse()?;
    // 提前解析, 防止后续错误
    let remove_server = args.remote_target.to_socket_addrs()?;

    let server = TcpListener::bind(server_addr).await?;

    show_msg(args.quiet, || {
        log(format!("服务器启动: {} -> {:?}", server_addr, remove_server).green());
    });

    let mut req_id = 0;
    loop {
        req_id += 1;
        let ctx = Context::new(args.clone(), req_id);

        let (local_stream, _) = server.accept().await?;

        spawn(async move {
            process_accept(ctx, local_stream).await;
        });
    }
}

async fn process_accept(ctx: Context, local_stream: TcpStream) {
    let local_addr = local_stream.local_addr().expect("获取SocketAddr失败");

    show_msg(ctx.args.quiet, || {
        log_with_req_id(ctx.req_id, format!("接收到连接: {}", local_addr,).green());
    });

    let rs = process_stream(local_stream, local_addr, ctx.clone()).await;

    show_msg(ctx.args.quiet, || {
        let close_msg = {
            let msg = format!("连接处理完成: {}, {:?}", local_addr, rs);
            match rs {
                Ok(_) => msg.green(),
                Err(_) => msg.red(),
            }
        };
        log_with_req_id(ctx.req_id, close_msg);
    });
}

fn show_msg<F>(quiet: bool, f: F)
where
    F: Fn(),
{
    if !quiet {
        f();
    }
}

fn log_with_req_id<D>(req_id: u64, msg: D)
where
    D: Display,
{
    let msg = format!("[req={}]{}", req_id.to_string().green(), msg);
    log(msg);
}

fn log<D>(msg: D)
where
    D: Display,
{
    let msg = fmt_with_ts(msg);
    println!("{}", msg);
}

fn fmt_with_ts<D>(msg: D) -> String
where
    D: Display,
{
    let now = Zoned::now();
    let now = now.strftime("%FT%X%.6f");
    format!("[{}]{}", now, msg)
}

async fn process_stream(
    local_stream: TcpStream,
    local_addr: SocketAddr,
    ctx: Context,
) -> CliResult {
    if ctx.args.remote_tls {
        process_stream_tls(local_stream, local_addr, ctx.clone()).await
    } else {
        process_stream_plain(local_stream, local_addr, ctx.clone()).await
    }
}

async fn process_stream_plain(
    local_stream: TcpStream,
    local_addr: SocketAddr,
    ctx: Context,
) -> CliResult {
    // 连接到远程
    let remote_stream: TcpStream = TcpStream::connect(&ctx.args.remote_target).await?;

    let remote_addr = remote_stream.peer_addr()?;

    show_msg(ctx.args.quiet, || {
        log_with_req_id(ctx.req_id, format!("连接成功REMOTE: {}", remote_addr));
    });

    bid_copy_stream(
        ctx,
        local_stream,
        remote_stream,
        local_addr.to_string(),
        remote_addr.to_string(),
    )
    .await;

    Ok(())
}

async fn bid_copy_stream<S1, S2>(
    ctx: Context,
    local_stream: S1,
    remote_stream: S2,
    local_addr: String,
    remote_addr: String,
) where
    S1: AsyncRead + AsyncWrite + 'static + Send,
    S2: AsyncRead + AsyncWrite + 'static + Send,
{
    let (local_reader, local_writer) = split(local_stream);

    let (remote_reader, remote_writer) = split(remote_stream);

    {
        let ctx = ctx.clone();
        let local_addr = local_addr.clone();
        let remote_addr = remote_addr.clone();
        spawn(async move {
            // 本地 -> 远端
            copy_reader_to_writer(
                local_reader,
                remote_writer,
                format!(
                    "{} >>>>> {}",
                    local_addr.to_string().green(),
                    remote_addr.to_string().yellow(),
                ),
                ctx,
            )
            .await;
        });
    }

    copy_reader_to_writer(
        remote_reader,
        local_writer,
        format!(
            "{} <<<<< {}",
            local_addr.to_string().yellow(),
            remote_addr.to_string().green(),
        ),
        ctx,
    )
    .await;

}

async fn copy_reader_to_writer<D, R, W>(mut r: R, mut w: W, msg_title: D, ctx: Context)
where
    D: Display,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; 65536];
    loop {
        let rs = r.read(&mut buf).await;
        match rs {
            Ok(0) => {
                show_msg(ctx.args.quiet, || {
                    log_with_req_id(ctx.req_id, format!("END:{}", msg_title,));
                });

                break;
            }
            Ok(size) => {
                let data = &buf[..size];
                display_data_msg(data, &msg_title, ctx.clone());
                let wrs = w.write_all(data).await;
                match wrs {
                    Ok(_) => {}
                    Err(err) => {
                        show_msg(ctx.args.quiet, || {
                            log_with_req_id(
                                ctx.req_id,
                                format!("END: {}, err={}", msg_title, err).red(),
                            );
                        });
                        break;
                    }
                }
            }
            Err(err) => {
                show_msg(ctx.args.quiet, || {
                    log_with_req_id(
                        ctx.req_id,
                        format!("ERR:{}, err={:?}", msg_title, err).red(),
                    );
                });
                break;
            }
        }
    }
}

fn display_data_msg(data: &[u8], msg_title: impl Display, ctx: Context) {
    show_msg(ctx.args.quiet, || {
        log_with_req_id(
            ctx.req_id,
            format!("{} LEN={}", msg_title, data.len().to_string().green()),
        );
        // 直接打印输出
        let mut out_bytes: Vec<u8> = vec![];

        let mask_bytes = data.iter().any(|x| {
            match *x {
                // 有特殊字段, 不适合在控制台显示
                0 | 0x1b => true,
                _ => false,
            }
        });

        if ctx.args.bytes_data {
            out_bytes.extend(
                "\n-----BEGIN BYTES-----\n"
                    .to_string()
                    .green()
                    .to_string()
                    .as_bytes(),
            );
            if mask_bytes {
                out_bytes.extend("MASK_BYTES...TO SEE HEX".as_bytes());
            } else {
                out_bytes.extend(data);
            }
            out_bytes.extend("\n-----END BYTES-----\n".yellow().to_string().as_bytes());
        }

        if ctx.args.hex || (mask_bytes && ctx.args.bytes_data) {
            let line_len: usize = ctx.args.hex_line;

            out_bytes.extend(
                "\n-----BEGIN HEX-----\n"
                    .to_string()
                    .green()
                    .to_string()
                    .as_bytes(),
            );
            for chunk in data.chunks(line_len) {
                let mut ascii_line = vec![];
                let mut hex_line = vec![];

                for b in chunk {
                    hex_line.extend(format!("{:02x} ", b).as_bytes());

                    ascii_line.push(if b.is_ascii_graphic() { *b } else { '.' as u8 });
                }

                out_bytes.extend(&hex_line);
                let c_len = chunk.len();
                if c_len > 0 {
                    let pad_len = line_len - c_len;
                    out_bytes.extend("   ".repeat(pad_len).as_bytes())
                }

                out_bytes.extend(&ascii_line);
                out_bytes.extend(b"\r\n");
            }

            out_bytes.extend("\n-----END HEX-----\n".yellow().to_string().as_bytes());
        }

        let _ = stdout().write_all(&out_bytes);
    });
}

#[derive(Debug)]
struct MyCustomCertVerifier(CryptoProvider);

/// 取消tls 域名认证
impl ServerCertVerifier for MyCustomCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn process_stream_tls(
    local_stream: TcpStream,
    local_addr: SocketAddr,
    ctx: Context,
) -> CliResult {
    // 连接到远程
    let remote_stream: TcpStream = TcpStream::connect(&ctx.args.remote_target).await?;

    let remote_addr = remote_stream.peer_addr()?;

    show_msg(ctx.args.quiet, || {
        log_with_req_id(ctx.req_id, format!("连接成功REMOTE(TLS): {}", remote_addr));
    });

    let remote_stream = connect_with_tls(remote_stream).await;

    bid_copy_stream(
        ctx,
        local_stream,
        remote_stream,
        local_addr.to_string(),
        remote_addr.to_string(),
    )
    .await;

    Ok(())
}

async fn connect_with_tls(stream: TcpStream) -> TlsStream<TcpStream> {
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(MyCustomCertVerifier(default_provider())))
        .with_no_client_auth();
    let server_name = ServerName::from(stream.peer_addr().expect("远端服务器连接错误").ip());

    let connector = TlsConnector::from(Arc::new(client_config));

    let stream = connector
        .connect(server_name, stream)
        .await
        .expect("连接远端服务器错误");

    stream
}
