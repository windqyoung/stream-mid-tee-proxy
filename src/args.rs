use clap::{ArgAction, Parser};

/// 代理tcp请求到远端服务器, 观察请求和响应的流量
///
/// 本地(明文) <---> 远端(明文/tls)
///
/// 应用只代理流量, 不进行压缩/解压缩
///
/// 如果使用 http, 可以提供 `Accept-Encoding: identity` 禁用压缩.
///
/// 可以从页面`https://curl.se/docs/caextract.html` 下载 cacert.pem, 使用环境变量 SSL_CERT_FILE 指定文件路径.
/// 
/// https://github.com/windqyoung/stream-mid-tee-proxy.git
/// 
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about)]
pub struct Args {
    /// 本地监听地址
    #[arg(short, long, default_value_t = String::from("0.0.0.0:8678"))]
    pub(crate) listen_addr: String,

    /// 远端服务器, ip:port
    #[arg(short, long)]
    pub(crate) remote_target: String,

    /// 远端服务器是否使用tls
    #[arg(long, default_value_t = false)]
    pub(crate) remote_tls: bool,

    /// 控制台不输出内容
    #[arg(short, long, default_value_t = false)]
    pub(crate) quiet: bool,

    /// 是否显示bytes数据
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub(crate) bytes_data: bool,

    /// 是否使用hex输出
    #[arg(long, default_value_t = false, action = ArgAction::Set)]
    pub(crate) hex: bool,

    /// hex显示使用的行宽
    #[arg(long, default_value_t = 32)]
    pub(crate) hex_line: usize,

    /// 是否要hex下方显示ascii信息
    #[arg(long, default_value_t = false)]
    pub(crate) hex_ascii_bottom: bool,

    /// 是否保存数据到文件中
    #[arg(long, default_value_t = false)]
    pub(crate) save: bool,

    /// 默认使用 pingora 来代理 http 请示.
    /// 可以切换成 tcp 流量代理.
    #[arg(long, default_value_t = false)]
    pub(crate) tcp: bool,

    /// 使用的http host头. 同时当做sni在用
    #[arg(long)]
    pub(crate) host: Option<String>,

    /// 要额外添加的http头
    #[arg(long)]
    pub(crate) header: Vec<String>,
}
