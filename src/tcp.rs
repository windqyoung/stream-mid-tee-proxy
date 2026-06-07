use crate::log::{display_data_msg, log_with_req_id, show_msg};
use colored::Colorize;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use std::fmt::Display;
use std::fs;
use std::fs::create_dir_all;
use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::context::{CliResult, Context};
use crate::{Args, log};

pub(crate) fn tcp_run(args: Args) -> CliResult {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(async { tcp_run_inner(args).await })
}

async fn tcp_run_inner(mut args: Args) -> CliResult {
    // 提前解析, 防止后续错误
    let remote_server = args.remote_target.to_socket_addrs()?;
    if let Some(addr) = remote_server.clone().next()
        && addr.port() == 443
    {
        args.remote_tls = true;
    }

    let server_addr: SocketAddr = args.listen_addr.parse()?;
    let server = create_listener(server_addr).await;
    show_msg(args.quiet, || {
        log::log(
            format!(
                "服务器启动: {} -> {:?}, 启动参数: {:?}",
                server.local_addr().expect("获取监听地址"),
                remote_server,
                args
            )
            .green(),
        );
    });

    spawn(async {
        log::start_print_log_co().await;
    });

    let mut req_id = 0;

    let log_dir = log::log_dir();

    loop {
        req_id += 1;
        let ctx = Context::new(args.clone(), req_id, log_dir.clone());

        let (local_stream, _) = server.accept().await?;

        spawn(async move {
            process_accept(ctx, local_stream).await;
        });
    }
}

async fn create_listener(mut server_addr: SocketAddr) -> TcpListener {
    let fix_port = server_addr.port();
    for port_offset in 0..100 {
        server_addr.set_port(fix_port + port_offset);
        let bind_rs = TcpListener::bind(server_addr).await;
        match bind_rs {
            Ok(bind) => {
                return bind;
            }
            Err(_) => {
                continue;
            }
        }
    }

    panic!("bind error, 未找到相应的端口");
}

async fn process_accept(ctx: Context, local_stream: TcpStream) {
    let local_addr = local_stream.local_addr().expect("获取SocketAddr失败");
    let peer_addr = local_stream.peer_addr().expect("获取客户端地址");

    show_msg(ctx.args.quiet, || {
        log_with_req_id(
            ctx.req_id,
            format!("接收到连接: {} on {}", peer_addr, local_addr,).green(),
        );
    });

    let rs = process_stream(local_stream, ctx.clone()).await;

    show_msg(ctx.args.quiet, || {
        let close_msg = {
            let msg = format!("连接处理完成: {} on {}, {:?}", peer_addr, local_addr, rs);
            match rs {
                Ok(_) => msg.green(),
                Err(_) => msg.red(),
            }
        };
        log_with_req_id(ctx.req_id, close_msg);
    });
}

async fn process_stream(local_stream: TcpStream, ctx: Context) -> CliResult {
    if ctx.args.remote_tls {
        process_stream_tls(local_stream, ctx.clone()).await
    } else {
        process_stream_plain(local_stream, ctx.clone()).await
    }
}

async fn process_stream_plain(local_stream: TcpStream, ctx: Context) -> CliResult {
    let local_addr: SocketAddr = local_stream.local_addr().expect("获取中间服务地址");
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

    let data_id = Arc::new(Mutex::new(0));

    // 创建两个任务，分别处理本地到远程和远程到本地的数据传输
    let task1 = {
        let data_id = Arc::clone(&data_id);
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
                data_id,
                "request".to_string(),
            )
            .await;
        })
    };

    let task2 = {
        let data_id = Arc::clone(&data_id);
        let ctx = ctx.clone();
        spawn(async move {
            // 远程 -> 本地
            copy_reader_to_writer(
                remote_reader,
                local_writer,
                format!(
                    "{} <<<<< {}",
                    local_addr.to_string().yellow(),
                    remote_addr.to_string().green(),
                ),
                ctx,
                data_id,
                "response".to_string(),
            )
            .await;
        })
    };

    // 等待两个任务完成，确保数据传输完全完成
    let _ = tokio::try_join!(task1, task2);
}

async fn copy_reader_to_writer<D, R, W>(
    mut r: R,
    mut w: W,
    msg_title: D,
    ctx: Context,
    data_id: Arc<Mutex<u64>>,
    stream_type: String,
) where
    D: Display,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if ctx.args.save {
        let rs = create_dir_all(&ctx.log_dir);
        show_msg(ctx.args.quiet, || {
            log_with_req_id(
                ctx.req_id,
                format!("保存日志: {}, {}, {:?}", &ctx.log_dir, stream_type, rs),
            );
        });
    }

    async fn close_write<D, W>(mut w: W, msg_title: D, ctx: Context)
    where
        D: Display,
        W: AsyncWrite + Unpin,
    {
        let rs = w.shutdown().await;
        show_msg(ctx.args.quiet, || {
            log_with_req_id(ctx.req_id, format!("关闭连接: {}, {:?}", msg_title, rs));
        });
    }

    let mut buf = vec![0; 65536];
    loop {
        let rs = r.read(&mut buf).await;

        let use_data_id = {
            let mut guard = data_id.lock().expect("data_id锁中毒");
            *guard += 1;
            *guard
        };

        match rs {
            Ok(0) => {
                show_msg(ctx.args.quiet, || {
                    log_with_req_id(ctx.req_id, format!("END:{}", msg_title,));
                });

                break;
            }
            Ok(size) => {
                let data = &buf[..size];

                if ctx.args.save {
                    let save_filename =
                        format!("{}/{}-{}.log", ctx.log_dir, ctx.req_id, stream_type);
                    let mut fs = fs::File::options()
                        .create(true)
                        .write(true)
                        .append(true)
                        .open(save_filename)
                        .expect("创建日志文件失败");
                    let rs = fs.write_all(data);
                    match rs {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }

                show_msg(ctx.args.quiet, || {
                    display_data_msg(data, &msg_title, ctx.clone(), use_data_id);
                });

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
                if err.kind() == ErrorKind::UnexpectedEof {
                    show_msg(ctx.args.quiet, || {
                        log_with_req_id(
                            ctx.req_id,
                            format!("END:{}, err=UnexpectedEof", msg_title).green(),
                        );
                    });
                } else {
                    show_msg(ctx.args.quiet, || {
                        log_with_req_id(
                            ctx.req_id,
                            format!("ERR:{}, err={:?}", msg_title, err).red(),
                        );
                    });
                }
                break;
            }
        }
    }

    close_write(w, msg_title, ctx).await;
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

async fn process_stream_tls(local_stream: TcpStream, ctx: Context) -> CliResult {
    let local_addr: SocketAddr = local_stream.local_addr().expect("获取中间服务地址");

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
