use crate::Args;
use crate::log;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

fn bid_log(msg: String) {
    log::log(msg);
}

pub(crate) fn bid_run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("启动双向复制tokio失败")
        .block_on(async { bid_inner_run(args).await })
}

async fn bid_inner_run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let local_addr = args.listen_addr;
    let remote_addr = args.remote_target;
    bid_log(format!("流量复制: {} => {}", local_addr, remote_addr));

    let server = TcpListener::bind(local_addr).await?;
    let sid = AtomicU64::new(0);

    loop {
        let accept_rs = server.accept().await;
        match accept_rs {
            Ok((stream, _)) => {
                let sid = sid.fetch_add(1, Ordering::SeqCst);
                let remote_addr = remote_addr.clone();
                tokio::spawn(async move {
                    process_bid_copy(stream, remote_addr, sid).await;
                });
            }
            Err(err) => {
                bid_log(format!("accept error: {}", err));
                continue;
            }
        }
    }
}

async fn process_bid_copy(mut stream: TcpStream, remote_addr: String, sid: u64) {
    let remote_stream = TcpStream::connect(&remote_addr).await;
    if let Err(e) = remote_stream {
        bid_log(format!("connect error: {}", e));
        return;
    }
    let mut remote_stream = remote_stream.unwrap();

    bid_log(format!(
        "[{sid}]复制中, {} <=> {} <=> {}",
        stream.peer_addr().expect("本地地址错误"),
        stream.local_addr().expect("本地代理错误"),
        remote_addr
    ));

    let copy_rs = copy_bidirectional(&mut stream, &mut remote_stream).await;
    match copy_rs {
        Ok(cpn) => {
            bid_log(format!("[{sid}]复制结束: {cpn:?}"));
        }
        Err(err) => {
            bid_log(format!("copy error: {}", err));
        }
    }
}
