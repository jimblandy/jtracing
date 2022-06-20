#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    clap::Parser,
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    libbpf_rs::{set_print, PerfBuffer, PerfBufferBuilder, PrintLevel},
    log::{debug, error, info, warn, LevelFilter},
    perf_event_open_sys::{self as peos, bindings::perf_event_attr},
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

#[path = "bpf/funccount.skel.rs"]
mod funccount;
use funccount::*;

type Event = funccount_bss_types::stacktrace_event;
unsafe impl Plain for Event {}

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg.trim_matches('\n')),
        PrintLevel::Info => log::info!("{}", msg.trim_matches('\n')),
        PrintLevel::Warn => log::warn!("{}", msg.trim_matches('\n')),
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

fn do_handle_event(_cpu: i32, data: &[u8]) {
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

    let comm = trans(event.comm.as_ptr());
    println!("{:<8}{:<18} @cpu{}", event.pid, comm, event.cpu_id);

    if event.kstack_sz > 0 {
        let number = event.kstack_sz as usize / std::mem::size_of::<u64>();
        println!("Kernel Stack ({} entries):", number);

        for i in 0..number {
            println!("  {:2} 0x{:016x}", i, event.kstack[i as usize]);
        }
    } else {
        println!("No Kernel Stack.");
    }

    if event.ustack_sz > 0 {
        let number = event.ustack_sz as usize / std::mem::size_of::<u64>();
        println!("User Stack ({} entries):", number);

        for i in 0..number {
            println!("  {:2} 0x{:016x}", i, event.ustack[i as usize]);
        }
    } else {
        println!("No User Stack.");
    }

    println!();
}

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

    let skel_builder = FunccountSkelBuilder::default();

    set_print(Some((PrintLevel::Debug, print_to_log)));

    let open_skel = skel_builder
        .open()
        .with_context(|| format!("Failed to open bpf."))?;

    let mut skel = open_skel
        .load()
        .with_context(|| format!("Failed to load bpf."))?;

    let handle_event = move |cpu: i32, data: &[u8]| {
        do_handle_event(cpu, data);
    };

    let perbuf = PerfBufferBuilder::new(skel.maps().pb())
        .sample_cb(handle_event)
        .pages(32)
        .build()
        .with_context(|| format!("Failed to create perf buffer"))?;

    let mut link = skel
        .progs_mut()
        .funccount()
        .attach_kprobe(false, "do_sys_open")
        .with_context(|| format!("Failed to attach do_sys_open."))?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        perbuf.poll(std::time::Duration::from_millis(100))?;
    }

    link.disconnect();

    Ok(())
}