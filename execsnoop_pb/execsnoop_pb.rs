#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    clap::Parser,
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    libbpf_rs::{set_print, PerfBuffer, PerfBufferBuilder, PrintLevel},
    log::{debug, error, info, warn},
    plain::Plain,
    std::{
        ffi::{CStr, CString},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Instant,
    },
    tracelib::bump_memlock_rlimit,
};

#[path = "bpf/execsnoop_pb.skel.rs"]
mod execsnoop_pb;
use execsnoop_pb::*;

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

#[derive(Parser, Debug)]
struct Cli {
    ///Trace process lives at least <DURATION> ms.
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,

    ///Use timestamp instead of date time.
    #[clap(short = 't', long)]
    timestamp: bool,
}

type Event = execsnoop_pb_bss_types::event;
unsafe impl Plain for Event {}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Off,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_time(false)
        .log_runtime(false)
        .build();

    bump_memlock_rlimit();

    let skel_builder = ExecsnoopPbSkelBuilder::default();
    set_print(Some((PrintLevel::Debug, print_to_log)));

    let mut open_skel = skel_builder.open().with_context(|| "Failed to open bpf.")?;

    open_skel.rodata().min_duration_ns = cli.duration * 1000000_u64;

    let mut skel = open_skel.load().with_context(|| "Faild to load bpf")?;

    let start = chrono::Local::now();
    let show_timestamp = cli.timestamp;
    let handle_event = move |_cpu: i32, data: &[u8]| {
        let mut event = Event::default();
        plain::copy_from_bytes(&mut event, data).expect("Corrupted event data");

        let trans = |a: *const i8| -> String {
            let ret = String::from("INVALID");
            unsafe {
                if let Ok(s) = CStr::from_ptr(std::mem::transmute(a)).to_str() {
                    return s.to_owned();
                }
            }
            ret
        };

        let now = chrono::Local::now();
        let timestamp_us = (now.timestamp_nanos() - start.timestamp_nanos()) / 1000;
        if event.exit_event != 0 {
            if show_timestamp {
                print!(
                    "{:^20.6}{:<7}{:<16}{:<8}{:<8}[{}]",
                    timestamp_us as f64 / 1000000_f64,
                    "EXIT",
                    trans(event.comm.as_ptr()),
                    event.pid,
                    event.ppid,
                    event.exit_code,
                );
            } else {
                print!(
                    "{:^20}{:<7}{:<16}{:<8}{:<8}[{}]",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "EXIT",
                    trans(event.comm.as_ptr()),
                    event.pid,
                    event.ppid,
                    event.exit_code,
                );
            }

            if event.duration_ns > 0 {
                print!(" ({}ms)", event.duration_ns / 1000000_u64);
            }
            println!();
        } else {
            if show_timestamp {
                print!(
                    "{:^20.6}{:<7}{:<16}{:<8}{:<8}[{}]",
                    timestamp_us as f64 / 1000000_f64,
                    "EXEC",
                    trans(event.comm.as_ptr()),
                    event.pid,
                    event.ppid,
                    trans(event.filename.as_ptr())
                );
            } else {
                print!(
                    "{:^20}{:<7}{:<16}{:<8}{:<8}[{}]",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "EXEC",
                    trans(event.comm.as_ptr()),
                    event.pid,
                    event.ppid,
                    trans(event.filename.as_ptr())
                );
            }

            if event.duration_ns > 0 {
                print!(" ({}ms)", event.duration_ns / 1000000_u64);
            }
            println!();
        }
    };

    let perbuf = PerfBufferBuilder::new(skel.maps().pb())
        .sample_cb(handle_event)
        .pages(32)
        .build()
        .with_context(|| "Failed to create perf buffer")?;

    skel.attach().with_context(|| "Faild to load bpf")?;

    println!(
        "{:^20} {:<7} {:<16} {:<8} {:<8} FILENAME/EXIT CODE",
        "TIME", "EVENT", "COMM", "PID", "PPID"
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        // ctrl-c will fail perbuf.poll()
        let _ = perbuf.poll(std::time::Duration::from_millis(100));
    }

    Ok(())
}
