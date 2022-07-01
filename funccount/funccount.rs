#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    byteorder::{BigEndian, LittleEndian, NativeEndian, ReadBytesExt},
    clap::Parser,
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    libbpf_rs::{set_print, MapFlags, PerfBuffer, PerfBufferBuilder, PrintLevel},
    log::{debug, error, info, warn, LevelFilter},
    perf_event_open_sys::{self as peos, bindings::perf_event_attr},
    plain::Plain,
    regex::Regex,
    std::mem::transmute,
    std::{
        ffi::{CStr, CString},
        io::Cursor,
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

use byteorder::ByteOrder;
use funccount::{funccount_bss_types::stacktrace_event, *};
use tracelib::symbolanalyzer::ExecMap;

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
    ///Trace for <DURATION> seconds (0 disabled).
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose.
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
    #[clap(short = 'c', default_value_t = true)]
    count: bool,

    ///Show relative time to previous record.
    #[clap(short = 'r')]
    relative: bool,

    ///Show relative time to previous record.
    #[clap(short = 'e')]
    experiment: bool,

    ///Only trace porcess with specified PID.
    #[clap(short = 'p', long)]
    pid: Option<i32>,

    ///Only trace porcess with specified NAME.
    #[clap(short = 'n', long)]
    name: Option<String>,

    #[clap()]
    args: Vec<String>,
}

struct StackcntResult {
    cnt: u64,
    stack: stacktrace_event,
    kstack: Vec<(u64, String)>,
    ustack: Vec<(u64, String, String)>,
}

fn do_handle_event(
    maps: &mut FunccountMaps,
    result: &mut Vec<StackcntResult>,
    symanalyzer: &mut SymbolAnalyzer,
    exec_hash: &mut HashMap<u32, ExecMap>,
) -> Result<()> {
    let stackcnt = maps.stackcnt();
    let stackmap = maps.stackmap();
    let mut sym_hash = HashMap::new();
    let mut pid_sym_hash: HashMap<(u32, u64), (u64, String, String)> = HashMap::new();

    for key in stackcnt.keys() {
        if let Ok(Some(data)) = stackcnt.lookup(&key, MapFlags::ANY) {
            let mut stack = Event::default();
            plain::copy_from_bytes(&mut stack, &key).expect("Corrupted event data");

            let mut cnt = 0_u64;
            plain::copy_from_bytes(&mut cnt, &data).expect("Corrupted event data");

            let mut kstack = vec![];
            let mut ustack = vec![];

            if stack.kstack > 0 {
                if let Ok(Some(ks)) = stackmap.lookup(&stack.kstack.to_ne_bytes(), MapFlags::ANY) {
                    let num = ks.len() / 8;
                    let mut i = 0_usize;

                    while i < num {
                        let addr = NativeEndian::read_u64(&ks[0 + 8 * i..0 + 8 * (i + 1)]);
                        if addr == 0 {
                            break;
                        }

                        let sym = sym_hash.entry(addr).or_insert(symanalyzer.ksymbol(addr)?);
                        kstack.push((addr, sym.to_string()));

                        i += 1;
                    }
                }
            }

            if stack.ustack > 0 {
                if let Ok(Some(us)) = stackmap.lookup(&stack.ustack.to_ne_bytes(), MapFlags::ANY) {
                    let num = us.len() / 8;
                    let mut i = 0_usize;

                    while i < num {
                        let addr = NativeEndian::read_u64(&us[0 + 8 * i..0 + 8 * (i + 1)]);
                        if addr == 0 {
                            break;
                        }
                        i += 1;

                        if let Some((sym_addr, symname, filename)) =
                            pid_sym_hash.get(&(stack.pid, addr))
                        {
                            ustack.push((*sym_addr, symname.to_string(), filename.to_string()));
                            continue;
                        }

                        if let Ok((sym_addr, symname, filename)) =
                            symanalyzer.usymbol(stack.pid, addr)
                        {
                            pid_sym_hash.insert(
                                (stack.pid, addr),
                                (sym_addr, symname.clone(), filename.clone()),
                            );
                            ustack.push((sym_addr, symname, filename));
                            continue;
                        }

                        if let Some(em) = exec_hash.get_mut(&stack.pid) {
                            if let Ok((sym_addr, symname, filename)) = em.symbol(addr) {
                                pid_sym_hash.insert(
                                    (stack.pid, addr),
                                    (sym_addr, symname.clone(), filename.clone()),
                                );
                                ustack.push((sym_addr, symname, filename));
                                continue;
                            }
                        }

                        pid_sym_hash.insert(
                            (stack.pid, addr),
                            (addr, "[unknown]".to_string(), "[unknown]".to_string()),
                        );
                        ustack.push((addr, "[unknown]".to_string(), "[unknown]".to_string()));
                    }
                }
            }

            result.push(StackcntResult {
                cnt,
                stack,
                kstack,
                ustack,
            });
        }
    }
    Ok(())
}

fn print_result(cli: Cli, result: &Vec<StackcntResult>, runtime_s: u64) -> Result<()> {
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

        println!(
            "{:<5} {:20} {:<8} {:9} {:9}",
            "PID", "Command", "Count", "Percent", "Counts/s"
        );
        let mut total = 0_u64;
        for event in result {
            total += event.cnt;
        }

        for event in result {
            let pid = event.stack.pid;
            let comm = trans(event.stack.comm.as_ptr());
            let cnt = event.cnt;

            println!(
                "{:<5} {:20} {:<8} {:5.2}% {:9}",
                pid,
                comm,
                cnt,
                (cnt as f64 / total as f64) * 100_f64,
                cnt / runtime_s
            );

            let mut fno = 0;
            if cli.stack {
                for (addr, sym) in event.kstack.iter() {
                    if cli.addr {
                        println!("    {:3} {:20x} {}", fno, addr, sym);
                    } else {
                        println!("    {:3} {}", fno, sym);
                    }

                    fno -= 1;
                }

                for (addr, symname, filename) in event.ustack.iter() {
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
        }

        return Ok(());
    }

    Ok(())
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

    let mut runtime_s;
    let mut exec_hash: HashMap<u32, ExecMap> = HashMap::new();
    let mut result = Vec::new();
    {
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

        let start = Instant::now();
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

        let exec_hash_ref = &mut exec_hash;
        let map = &skel.maps();
        let try_to_store_pid_info = cli.experiment;

        let mut store_pid_info = move || {
            if try_to_store_pid_info {
                let stackcnt = map.stackcnt();
                for key in stackcnt.keys() {
                    let mut stack = Event::default();
                    plain::copy_from_bytes(&mut stack, &key).expect("Corrupted event data");
                    if exec_hash_ref.get(&stack.pid).is_none() {
                        if let Ok(em) = ExecMap::new(stack.pid) {
                            exec_hash_ref.insert(stack.pid, em);
                        }
                    }
                }
            }
        };

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
            store_pid_info();

            if cli.duration > 0 && start.elapsed().as_secs() > cli.duration {
                break;
            }
        }
        runtime_s = start.elapsed().as_secs();
    }

    let start2 = Instant::now();
    println!("\nTracing finished, Processing data...");

    let mut symanalyzer = SymbolAnalyzer::new(None)?;
    do_handle_event(
        &mut skel.maps(),
        &mut result,
        &mut symanalyzer,
        &mut exec_hash,
    )?;
    runtime_s += start2.elapsed().as_secs();
    result.sort_by(|a, b| b.cnt.partial_cmp(&a.cnt).unwrap());
    print_result(cli, &result, runtime_s)?;

    Ok(())
}
