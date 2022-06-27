#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    clap::Parser,
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    libbpf_rs::{set_print, PerfBuffer, PerfBufferBuilder, PrintLevel},
    log::{debug, error, info, warn, LevelFilter},
    perf_event_open_sys::{self as peos, bindings::perf_event_attr},
    plain::Plain,
    regex::Regex,
    std::{
        ffi::{CStr, CString},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tracelib::{bump_memlock_rlimit, ElfFile, SymbolAnalyzer},
};

#[path = "bpf/funccount.skel.rs"]
mod funccount;
use std::collections::HashMap;

use funccount::*;

type Event = funccount_bss_types::stacktrace_event;
unsafe impl Plain for Event {}

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::trace!("{}", msg.trim_matches('\n')),
        PrintLevel::Info => log::info!("{}", msg.trim_matches('\n')),
        PrintLevel::Warn => log::warn!("{}", msg.trim_matches('\n')),
    }
}

#[derive(Parser, Debug)]
struct Cli {
    ///Trace process lives at least <DURATION> second.
    ///Disabled when specified 0.
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,

    ///Show symbol address.
    #[clap(short = 'a')]
    addr: bool,

    ///Show file informaton.
    #[clap(short = 'f')]
    file: bool,

    ///Show stack informaton.
    #[clap(short = 's')]
    stack: bool,

    ///Show count informaton.
    #[clap(short = 'c')]
    count: bool,

    ///Show relative time to previous record.
    #[clap(short = 'r')]
    relative: bool,

    ///Only trace porcess with specified PID.
    #[clap(short = 'p')]
    pid: Option<i32>,

    #[clap()]
    args: Vec<String>,
}

fn do_handle_event(_cpu: i32, data: &[u8], result: &mut Vec<Event>) {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Corrupted event data");
    result.push(event);
}

fn print_result(symanalyzer: &mut SymbolAnalyzer, cli: Cli, result: &Vec<Event>) -> Result<()> {
    let trans = |a: *const i8| -> String {
        let ret = String::from("INVALID");
        unsafe {
            if let Ok(s) = CStr::from_ptr(std::mem::transmute(a)).to_str() {
                return s.to_owned();
            }
        }
        ret
    };

    println!();

    if cli.count {
        if result.is_empty() {
            return Err(Error::msg("No entry."));
        }

        let mut hashmap = HashMap::<u32, (String, u32)>::new();
        for event in result {
            let pid = event.pid;
            let comm = trans(event.comm.as_ptr());

            let (_comm, cnt) = &mut hashmap.entry(pid).or_insert((comm, 0));
            *cnt += 1;
        }

        println!(
            "{:<5} {:20} {:<8} {:9}",
            "PID", "Command", "Count", "Percent"
        );
        let total = result.len() as f64;
        for key in hashmap.keys() {
            let (comm, cnt) = hashmap.get(key).unwrap();
            println!(
                "{:<5} {:20} {:<8} {:5.2}%",
                key,
                comm,
                cnt,
                ((*cnt as f64) / total) * 100_f64
            );
        }

        return Ok(());
    }

    let mut previous_us = 0_u64;

    if !cli.stack {
        if cli.relative {
        println!(
            "{:<5} {:<12} {:<5} {:<18} {}",
            "No", "Timestamp(R)", "PID", "Command", "CPU"
        );
        } else {
        println!(
            "{:<5} {:<12} {:<5} {:<18} {}",
            "No", "Timestamp", "PID", "Command", "CPU"
        );
        }
    }
    for (i, event) in result.iter().enumerate() {
        let comm = trans(event.comm.as_ptr());
        let us = event.ts / 1000;

        if cli.relative {
            let mut diff_us = us - previous_us;
            if previous_us == 0 {
                diff_us = 0;
            }
            previous_us = us;

            println!(
                "{:<5} {:<12} {:<5} {:<18} @cpu{}",
                i + 1,
                diff_us,
                event.pid,
                comm,
                event.cpu_id
            );
        } else {
            println!(
                "{:<5} {:<12.6} {:<5} {:<18} @cpu{}",
                i + 1,
                (us as f64) / 1000000_f64,
                event.pid,
                comm,
                event.cpu_id
            );
        }

        if cli.stack {
            let mut fno = 0;
            if event.kstack_sz > 0 {
                let number = event.kstack_sz as usize / std::mem::size_of::<u64>();

                for i in 0..number {
                    let addr = event.kstack[i as usize];
                    if cli.addr {
                        println!("    {:3} {:20x} {}", fno, addr, symanalyzer.ksymbol(addr)?);
                    } else {
                        println!("    {:3} {}", fno, symanalyzer.ksymbol(addr)?);
                    }

                    fno -= 1;
                }
            }

            if event.ustack_sz > 0 {
                let number = event.ustack_sz as usize / std::mem::size_of::<u64>();

                for i in 0..number {
                    let addr = event.ustack[i as usize];
                    let (addr, symname, filename) = symanalyzer.usymbol(event.pid, addr)?;
                    let mut filename_str = String::new();
                    if cli.file {
                        filename_str = format!("({})", filename);
                    }

                    if cli.addr {
                        println!("    {:3} {:20x} {} {}", fno, addr, symname, filename_str);
                    } else {
                        println!("    {:3} {} {}", fno, symname, filename_str);
                    }

                    fno -= 1;
                }
            }

            println!();
        }
    }
    Ok(())
}

fn lost_handle(_cpu: i32, lost_count: u64) {
    println!("lost_handle: {}", lost_count);
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        2 => log::LevelFilter::Trace,
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

    let mut open_skel = skel_builder
        .open()
        .with_context(|| format!("Failed to open bpf."))?;

    open_skel.bss().self_pid = std::process::id() as i32;

    if let Some(pid) = cli.pid {
        open_skel.bss().target_pid = pid;
    }

    let mut skel = open_skel
        .load()
        .with_context(|| format!("Failed to load bpf."))?;

    let mut result = Vec::new();
    {
        let result_ref = &mut result;
        let handle_event = move |cpu: i32, data: &[u8]| do_handle_event(cpu, data, result_ref);

        let perbuf = PerfBufferBuilder::new(skel.maps().pb())
            .sample_cb(handle_event)
            .lost_cb(lost_handle)
            .pages(32)
            .build()
            .with_context(|| format!("Failed to create perf buffer"))?;

        let mut links = vec![];
        for arg in &cli.args {
            let mut processed = false;

            let tre = Regex::new(r"t:([a-z|0-9|_]+):([a-z|0-9|_]+)")?;
            if tre.is_match(&arg) {
                for g in tre.captures_iter(&arg) {
                    let tp_category = &g[1];
                    let tp_name = &g[2];

                    println!("Attaching Tracepoint {}:{}.", tp_category, tp_name);
                    let link = skel
                        .progs_mut()
                        .stacktrace_tp()
                        .attach_tracepoint(tp_category, tp_name)
                        .with_context(|| format!("Failed to attach {}.", arg))?;

                    links.push(link);
                    processed = true;
                }
            }
            if processed {
                continue;
            }

            let mut pid = -1;
            if let Some(p) = cli.pid {
                if p > 0 {
                    pid = p;
                }
            }

            let tre = Regex::new(r"u:(.+):(.+)")?;
            if tre.is_match(&arg) {
                for g in tre.captures_iter(&arg) {
                    let file = &g[1];
                    let symbol = &g[2];

                    let elf_file = ElfFile::new(file)?;
                    let offset = elf_file.find_addr(symbol)? as usize;

                    println!("Attaching uprobe {}:{}.", file, symbol);
                    /*
                     * Parameter
                     *  pid > 0: target process to trace
                     *  pid == 0 : trace self
                     *  pid == -1 : trace all processes
                     * See bpf_program__attach_uprobe()
                     */
                    let link = skel
                        .progs_mut()
                        .stacktrace_ub()
                        .attach_uprobe(false, pid, file, offset)
                        .with_context(|| format!("Failed to attach {}.", arg))?;

                    links.push(link);
                    processed = true;
                }
            }

            if processed {
                continue;
            }

            let tre = Regex::new(r"(k:)*([a-z|0-9|_]+)")?;
            if tre.is_match(&arg) {
                for g in tre.captures_iter(&arg) {
                    let func_name = &g[2];

                    println!("Attaching Kprobe {}.", func_name);
                    let link = skel
                        .progs_mut()
                        .stacktrace_kb()
                        .attach_kprobe(false, func_name)
                        .with_context(|| format!("Failed to attach {}.", arg))?;

                    links.push(link);
                    processed = true;
                }
            }
            if processed {
                continue;
            }
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        if cli.duration > 0 {
            println!("Tracing for {} seconds, Type Ctrl-C to stop.", cli.duration);
        } else {
            println!("Tracing... Type Ctrl-C to stop.");
        }
        let start = Instant::now();
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
            if cli.duration > 0 && start.elapsed().as_secs() > cli.duration {
                break;
            }
        }

        perbuf.consume()?;
    }

    println!("\nTracing finished, Processing data...");

    let mut symanalyzer = SymbolAnalyzer::new(None)?;
    result.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap());
    print_result(&mut symanalyzer, cli, &result)?;

    Ok(())
}
