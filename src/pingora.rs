use crate::context::Context;
use crate::log::{display_data_msg, log, log_dir, log_with_req_id, show_msg, start_print_log_co};
use crate::{log, Args};
use async_trait::async_trait;
use bytes::Bytes;
use colored::Colorize;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::{
    background_service, http_proxy_service, HttpPeer, ProxyHttp, Server, Session,
};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::spawn;

pub(crate) fn pingora_run(mut args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let remote_server = args.remote_target.to_socket_addrs()?;
    if let Some(addr) = remote_server.clone().next()
        && addr.port() == 443
    {
        args.remote_tls = true;
    }

    let mut my_server = Server::new(None).expect("创建pingora服务失败");
    my_server.bootstrap();

    let back_svc = background_service("日志", LogBackgroundService { args: args.clone() });

    let back_hd = my_server.add_service(back_svc);

    // 添加代理端口
    let mut upstream_service =
        http_proxy_service(&my_server.configuration, UpstreamProxy::new(args.clone()));

    upstream_service.add_tcp(&args.listen_addr.clone());

    let up_hd = my_server.add_service(upstream_service);
    up_hd.add_dependency(&back_hd);

    my_server.run(Default::default());

    Ok(())
}

struct LogBackgroundService {
    args: Args,
}

#[async_trait]
impl BackgroundService for LogBackgroundService {
    async fn start(&self, _shutdown: ShutdownWatch) {
        spawn(async { start_print_log_co().await });
        show_msg(self.args.quiet, || {
            log(format!(
                "服务器启动: {} -> {}, 服务参数: {:?}",
                self.args.listen_addr, self.args.remote_target, self.args
            )
            .green());
        });
    }
}

struct UpstreamProxy {
    req_id: AtomicU64,
    args: Args,
}

impl UpstreamProxy {
    fn new(args: Args) -> Self {
        Self {
            args,
            req_id: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl ProxyHttp for UpstreamProxy {
    type CTX = Context;

    fn new_ctx(&self) -> Self::CTX {
        Context::new(
            self.args.clone(),
            self.req_id.fetch_add(1, Ordering::SeqCst),
            log_dir(),
        )
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let address = ctx.args.remote_target.clone();
        let tls = self.args.remote_tls;
        let sni = ctx
            .args
            .host
            .clone()
            .or(Some("".to_string()))
            .expect("此处不应该报错.");

        show_msg(ctx.args.quiet, || {
            log_with_req_id(
                ctx.req_id,
                format!(
                    "接收到请求: {} >>>>> {} (sni: {})",
                    session
                        .client_addr()
                        .map_or(String::from("无客户端地址"), |x| x.to_string())
                        .green(),
                    address.to_string().yellow(),
                    sni
                )
            )
        });

        let peer = HttpPeer::new(address, tls, sni);
        Ok(Box::new(peer))
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let msg_title = format!(
            "{} >>>>> {}",
            session
                .client_addr()
                .map_or(String::from("无客户端地址"), |x| x.to_string())
                .green(),
            ctx.args.remote_target.yellow()
        );

        if body.is_some() {
            ctx.sub_id += 1;
            show_msg(ctx.args.quiet, || {
                display_data_msg(body.as_ref().unwrap(), &msg_title, ctx.clone(), ctx.sub_id);
            });

            log::save(ctx, "request_body".to_string(), body.as_ref().unwrap());
        }

        if end_of_stream {
            show_msg(ctx.args.quiet, || {
                log_with_req_id(ctx.req_id, format!("END: {}", msg_title).red());
            })
        }

        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if ctx.args.host.is_some() {
            upstream_request
                .insert_header("Host", ctx.args.host.clone().expect("此处取头不会报错"))?;
            show_msg(ctx.args.quiet, || {
                log_with_req_id(
                    ctx.req_id,
                    format!("Host已添加: {:?}", ctx.args.host.clone()),
                )
            });
        }
        for hd_str in &ctx.args.header {
            // 指添加头
            if let Some(pos) = hd_str.find(':') {
                let name = hd_str[..pos].trim().to_string();
                let value = hd_str[pos + 1..].trim().to_string();
                upstream_request.insert_header(name.clone(), value.clone())?;
                show_msg(ctx.args.quiet, || {
                    log_with_req_id(ctx.req_id, format!("已添加HTTP头: {}: {}", name, value))
                });
            }
        }

        show_msg(ctx.args.quiet, || {
            log_with_req_id(ctx.req_id, format!("HTTP请求: {:?}", upstream_request))
        });

        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        show_msg(ctx.args.quiet, || {
            let msg_title = format!(
                "HTTP响应: {} <<<<< {}",
                session
                    .client_addr()
                    .map_or(String::from("无客户端地址"), |x| x.to_string())
                    .yellow(),
                ctx.args.remote_target.to_string().green()
            );
            log_with_req_id(ctx.req_id, msg_title);
            log_with_req_id(ctx.req_id, format!("{:?}", upstream_response));
        });

        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        let msg_title = format!(
            "{} <= {}",
            session
                .client_addr()
                .map_or(String::from("无客户端地址"), |x| x.to_string())
                .yellow(),
            ctx.args.remote_target.to_string().green(),
        );

        if body.is_some() {
            ctx.sub_id += 1;
            show_msg(ctx.args.quiet, || {
                display_data_msg(
                    body.clone().unwrap().as_ref(),
                    &msg_title,
                    ctx.clone(),
                    ctx.sub_id,
                );
            });

            log::save(ctx, "response_body".to_string(), body.as_ref().unwrap());
        }

        if end_of_stream {
            show_msg(ctx.args.quiet, || {
                log_with_req_id(ctx.req_id, format!("END: {}", msg_title).red());
            })
        }

        Ok(None)
    }
}
