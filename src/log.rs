use colored::Colorize;
use jiff::Zoned;
use std::fmt::Display;
use std::fs;
use std::fs::create_dir_all;
use std::io::{Write, stdout};
use std::sync::{LazyLock, Mutex};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::context::Context;

enum LogMessage {
    String(String),
    Bytes(Vec<u8>),
}

static GLOBAL_SENDER: LazyLock<Mutex<Option<UnboundedSender<LogMessage>>>> =
    LazyLock::new(|| return Mutex::new(None));

pub(crate) async fn start_print_log_co() {
    let (tx, mut rx) = unbounded_channel::<LogMessage>();

    {
        let mut lock = GLOBAL_SENDER.lock().expect("锁中毒1");

        if (*lock).is_some() {
            eprintln!("全局日志第二次启动, 忽略...");
            return;
        }

        *lock = Some(tx);
    }

    while let Some(data) = rx.recv().await {
        match data {
            LogMessage::String(str_msg) => {
                println!("[P{}]{}", line!(), str_msg);
            }
            LogMessage::Bytes(bytes_msg) => {
                let _ = stdout().lock().write_all(&bytes_msg);
            }
        }
    }
}

fn log_bytes(out_bytes: Vec<u8>) {
    let lock = GLOBAL_SENDER.lock().expect("锁中毒3");
    match &*lock {
        None => {
            let _ = stdout().lock().write_all(&out_bytes);
        }
        Some(tx) => {
            let rs = tx.send(LogMessage::Bytes(out_bytes.clone()));
            match rs {
                Ok(_) => {}
                Err(_) => {
                    let _ = stdout().lock().write_all(&out_bytes);
                }
            }
        }
    }
}

pub(crate) fn log<D>(msg: D)
where
    D: Display,
{
    let msg = fmt_with_ts(msg);
    let lock = GLOBAL_SENDER.lock().expect("锁中毒2");
    match &*lock {
        None => {
            println!("[L1.{}]{}", line!(), msg.clone());
        }
        Some(tx) => {
            let rs = tx.send(LogMessage::String(msg.clone()));
            match rs {
                Ok(_) => {}
                Err(_) => {
                    println!("[L2.{}]{}", line!(), msg);
                }
            }
        }
    }
}

fn fmt_with_ts<D>(msg: D) -> String
where
    D: Display,
{
    let now = Zoned::now();
    let now = now.strftime("%FT%X%.6f");
    format!("[{}]{}", now, msg)
}

pub(crate) fn log_dir() -> String {
    let now = Zoned::now();
    format!(
        "target/stream-log/{}-{:02}-{:02}T{:02}-{:02}-{:02}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

pub(crate) fn show_msg<F>(quiet: bool, f: F)
where
    F: Fn(),
{
    if !quiet {
        f();
    }
}

pub(crate) fn log_with_req_id<ID, D>(req_id: ID, msg: D)
where
    ID: Display,
    D: Display,
{
    let msg = format!("[req={}]{}", req_id.to_string().green(), msg);
    log(msg);
}

pub(crate) fn display_data_msg(data: &[u8], msg_title: impl Display, ctx: Context, data_id: u64) {
    let req_id = format!("{}.{}", ctx.req_id, data_id);
    log_with_req_id(
        req_id,
        format!("{} LEN={}", msg_title, data.len().to_string().green()),
    );
    // 直接打印输出
    let mut out_bytes: Vec<u8> = vec![];

    let utf8_rs = String::from_utf8(data.to_vec());
    let mask_bytes = utf8_rs.is_err();

    if ctx.args.bytes_data {
        out_bytes.extend(
            format!("\n-----BEGIN BYTES----- {}\n", msg_title)
                .green()
                .to_string()
                .as_bytes(),
        );
        out_bytes.extend(String::from_utf8_lossy(data).as_bytes());
        out_bytes.extend("\n-----END BYTES-----\n".yellow().to_string().as_bytes());
    }

    if ctx.args.hex || (mask_bytes && ctx.args.bytes_data) {
        let line_len: usize = ctx.args.hex_line;

        out_bytes.extend(
            format!("\n-----BEGIN HEX----- {}\n", msg_title)
                .green()
                .to_string()
                .as_bytes(),
        );
        for chunk in data.chunks(line_len) {
            let mut ascii_line = vec![];
            let mut hex_line = vec![];

            for (idx, b) in chunk.iter().enumerate() {
                hex_line.extend(format!("{:02x}", b).as_bytes());

                hex_line.push(if idx % 8 == 7 { '|' as u8 } else { ' ' as u8 });

                let a_char = if b.is_ascii_graphic() { *b } else { '.' as u8 };

                ascii_line.push(a_char);
            }

            out_bytes.extend(&hex_line);

            let c_len = chunk.len();
            if c_len > 0 {
                let pad_len = line_len - c_len;
                out_bytes.extend("   ".repeat(pad_len).as_bytes())
            }

            out_bytes.extend(&ascii_line);
            out_bytes.extend(b"\r\n");

            if ctx.args.hex_ascii_bottom {
                let hex_ascii_line = chunk_to_hex_ascii(chunk);

                out_bytes.extend(hex_ascii_line);
                out_bytes.extend(b"\r\n");
            }
        }

        out_bytes.extend("\n-----END HEX-----\n".yellow().to_string().as_bytes());
    }

    log_bytes(out_bytes);
}

pub fn chunk_to_hex_ascii(chunk: &[u8]) -> Vec<u8> {
    let mut hex_ascii_line: Vec<u8> = vec![];
    // 计算 utf8 可显示的字符

    let mut idx = 0;
    while idx < chunk.len() {
        let b = chunk[idx];
        let c = b as char;
        idx += 1;
        match c {
            '\r' | '\n' | '\t' => {
                hex_ascii_line.extend(format!("{} ", c.escape_default()).as_bytes())
            }
            '\x1b' => {
                hex_ascii_line.extend("\\e ".as_bytes());
            }
            graphic if c.is_ascii_graphic() => {
                hex_ascii_line.extend(format!("{}  ", graphic).as_bytes());
            }
            _ => {
                hex_ascii_line.extend(".  ".as_bytes());
            }
        }
    }
    hex_ascii_line
}

pub(crate) fn save(ctx: &Context, stream_type: String, data: &[u8]) {
    if !ctx.args.save {
        return;
    }

    let rs = create_dir_all(&ctx.log_dir);
    show_msg(ctx.args.quiet, || {
        log_with_req_id(
            ctx.req_id,
            format!("保存日志: {}, {}, {:?}", &ctx.log_dir, stream_type, rs),
        );
    });

    let save_filename = format!("{}/{}-{}.log", ctx.log_dir, ctx.req_id, stream_type);
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
