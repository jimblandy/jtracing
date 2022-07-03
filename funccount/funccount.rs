#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    byteorder::ByteOrder,
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
        collections::HashMap,
        ffi::{CStr, CString},
        io::Cursor,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, ElfFile, ExecMap, SymbolAnalyzer},
};

#[path = "bpf/funccount.skel.rs"]
mod funccount;

use funccount::*;

type StackEvent = funccount_bss_types::stacktrace_event;
unsafe impl Plain for StackEvent {}

type ExecTraceEvent = funccount_bss_types::exectrace_event;
unsafe impl Plain for ExecTraceEvent {}

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

    ///Trace function execution.
    #[clap(short = 'e')]
    exec: bool,

    ///Trace function execution.
    #[clap(short = 'c', long)]
    count: Option<u32>,

    ///Show relative time to previous record.
    #[clap(short = 'r')]
    relative: bool,

    ///Only trace porcess with specified PID.
    #[clap(short = 'p', long)]
    pid: Option<i32>,

    ///Only trace porcess with specified NAME.
    #[clap(short = 'n', long)]
    name: Option<String>,

    #[clap()]
    args: Vec<String>,
}

enum TraceResult {
    Stack(StackTraceResult),
    Exec(ExecTraceResult),
}

struct ExecTraceResult {
    ts: u64,
    entry: ExecTraceEvent,
}

struct StackTraceResult {
    cnt: u64,
    stack: StackEvent,
    kstack: Vec<(u64, String)>,
    ustack: Vec<(u64, String, String)>,
}

fn process_events(
    cli: &Cli,
    maps: &mut FunccountMaps,
    result: &mut Vec<TraceResult>,
    symanalyzer: &mut SymbolAnalyzer,
    exec_map_hash: &mut HashMap<u32, ExecMap>,
) -> Result<()> {
    if cli.exec {
        let exectime = maps.exectime();

        for key in exectime.keys() {
            let mut entry = ExecTraceEvent::default();
            plain::copy_from_bytes(&mut entry, &key).expect("Corrupted event data");
            let ts: u64 = NativeEndian::read_u64(&entry.ts);
            result.push(TraceResult::Exec(ExecTraceResult { ts, entry }));
        }
    } else {
        let stackcnt = maps.stackcnt();
        let stackmap = maps.stackmap();
        let mut sym_hash = HashMap::new();
        let mut pid_sym_hash: HashMap<(u32, u64), (u64, String, String)> = HashMap::new();

        for key in stackcnt.keys() {
            if let Ok(Some(data)) = stackcnt.lookup(&key, MapFlags::ANY) {
                let mut stack = StackEvent::default();
                plain::copy_from_bytes(&mut stack, &key).expect("Corrupted event data");

                let mut cnt = 0_u64;
                plain::copy_from_bytes(&mut cnt, &data).expect("Corrupted event data");

                let mut kstack = vec![];
                let mut ustack = vec![];

                if stack.kstack > 0 {
                    if let Ok(Some(ks)) =
                        stackmap.lookup(&stack.kstack.to_ne_bytes(), MapFlags::ANY)
                    {
                        let num = ks.len() / 8;
                        let mut i = 0_usize;

                        while i < num {
                            let addr = NativeEndian::read_u64(&ks[8 * i..8 * (i + 1)]);
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
                    if let Ok(Some(us)) =
                        stackmap.lookup(&stack.ustack.to_ne_bytes(), MapFlags::ANY)
                    {
                        let num = us.len() / 8;
                        let mut i = 0_usize;

                        while i < num {
                            let addr = NativeEndian::read_u64(&us[8 * i..8 * (i + 1)]);
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

                            if let Some(em) = exec_map_hash.get_mut(&stack.pid) {
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

                result.push(TraceResult::Stack(StackTraceResult {
                    cnt,
                    stack,
                    kstack,
                    ustack,
                }));
            }
        }
    }
    Ok(())
}

fn print_result(cli: &Cli, result: &Vec<TraceResult>, runtime_s: u64) -> Result<()> {
    let runtime_s = if runtime_s == 0 { 1 } else { runtime_s };

    println!();

    let mut result_stack = vec![];
    let mut result_exec = vec![];
    let mut total_cnt = 0_u64;

    for res in result {
        match res {
            TraceResult::Stack(sr) => {
                total_cnt += sr.cnt;
                result_stack.push(sr)
            }
            TraceResult::Exec(ex) => result_exec.push(ex),
        }
    }

    result_stack.sort_by(|&a, &b| b.cnt.partial_cmp(&a.cnt).unwrap());
    result_exec.sort_by(|&a, &b| a.ts.partial_cmp(&b.ts).unwrap());

    let show_limit = cli.count.unwrap_or(u32::MAX);

    if !result_exec.is_empty() {
        let mut show_count = 0;

        println!("{:<12} {:<5} {:20} ", "Timestamp", "PID", "Command");
        let mut ts_previous = 0_u64;
        for event in result_exec {
            let pid = event.entry.pid;
            let comm = unsafe { bytes_to_string(event.entry.comm.as_ptr()) };
            let ts = event.ts / 1000;
            let ts_show;

            if cli.relative {
                if ts_previous == 0 {
                    ts_show = 0;
                } else {
                    ts_show = ts - ts_previous;
                }
                ts_previous = ts;
            } else {
                ts_show = ts;
            }

            println!(
                "{:<12.6} {:<5} {:20}",
                ts_show as f64 / 1000000_f64,
                pid,
                comm,
            );

            show_count += 1;
            if show_count >= show_limit {
                break;
            }
        }
    }

    if !result_stack.is_empty() {
        let mut show_count = 0;

        println!(
            "Total count: {}, {}counts/s",
            total_cnt,
            total_cnt / runtime_s
        );
        println!(
            "  {:<5} {:20} {:<8} {:9} {:9}",
            "PID", "COMMAND", "COUNTS", "PERCENT", "COUNTS/s"
        );

        if !cli.stack {
            let mut pid_cnt = HashMap::new();

            for event in result_stack {
                let pid = event.stack.pid;
                let comm = unsafe { bytes_to_string(event.stack.comm.as_ptr()) };
                let cnt = event.cnt;

                let (_comm_, cnt_) = pid_cnt.entry(pid).or_insert((comm, 0_u64));
                *cnt_ += cnt;
            }

            for (_, (pid, (comm, cnt))) in pid_cnt.iter().enumerate() {
                println!(
                    "  {:<5} {:20} {:<8} {:5.2}% {:9}",
                    pid,
                    comm,
                    cnt,
                    (*cnt as f64 / total_cnt as f64) * 100_f64,
                    cnt / runtime_s
                );
            }
        } else {
            for event in result_stack {
                let pid = event.stack.pid;
                let comm = unsafe { bytes_to_string(event.stack.comm.as_ptr()) };
                let cnt = event.cnt;

                println!(
                    "{:<5} {:20} {:<8} {:5.2}% {:9}",
                    pid,
                    comm,
                    cnt,
                    (cnt as f64 / total_cnt as f64) * 100_f64,
                    cnt / runtime_s
                );

                let mut fno = 0;
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

                show_count += 1;
                if show_count >= show_limit {
                    break;
                }
            }
        }

        return Ok(());
    }

    Ok(())
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
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

    let mut open_skel = skel_builder.open().with_context(|| "Failed to open bpf.")?;

    open_skel.bss().self_pid = std::process::id() as i32;

    if let Some(pid) = cli.pid {
        open_skel.bss().target_pid = pid;
    } else {
        open_skel.bss().target_pid = -1;
    }

    if cli.exec {
        open_skel.bss().trace_type = 1;

        if cli.stack {
            log::warn!("Show stack option -s is unused when using -e.");
            cli.stack = false;
        }
    } else if cli.relative {
        log::warn!("Show relative time option -r is unused when -e is unused.");
        cli.relative = false;
    }

    if !cli.stack && cli.addr {
        log::warn!("Show addr option -a is unused when -s is unused.");
        cli.addr = false;
    }

    if !cli.stack && cli.file {
        log::warn!("Show file option -f is unused when -s is unused.");
        cli.file = false;
    }

    let mut skel = open_skel.load().with_context(|| "Failed to load bpf.")?;

    let mut result = Vec::new();
    let mut links = vec![];
    let mut exec_map_hash = HashMap::<u32, ExecMap>::new();
    let mut runtime_s;
    {
        let exec_map_hash_ref = &mut exec_map_hash;

        let handle_exec_trace = move |_cpu: i32, data: &[u8]| {
            let pid = NativeEndian::read_u32(data);

            match ExecMap::new(pid) {
                Ok(em) => {
                    exec_map_hash_ref.insert(pid, em);
                }
                Err(e) => {
                    if pid != 0 {
                        jwarn!("Failed to read maps for pid {}: {}", pid, e)
                    }
                }
            }
        };

        let perfbuf = PerfBufferBuilder::new(skel.maps().exectrace_pb())
            .sample_cb(handle_exec_trace)
            .pages(32)
            .build()
            .with_context(|| "Failed to create perf buffer")?;

        for arg in &cli.args {
            let mut processed = false;

            let tre = Regex::new(r"t:([a-z|0-9|_]+):([a-z|0-9|_]+)")?;
            if tre.is_match(arg) {
                for g in tre.captures_iter(arg) {
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
            if tre.is_match(arg) {
                for g in tre.captures_iter(arg) {
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
            if tre.is_match(arg) {
                for g in tre.captures_iter(arg) {
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

        let mut timeout = if cli.duration > 0 {
            (cli.duration * 1000) as u64
        } else {
            100
        };

        while running.load(Ordering::SeqCst) {
            let _ = perfbuf.poll(std::time::Duration::from_millis(timeout));

            if cli.duration > 0 {
                let passed = start.elapsed().as_millis() as u64;
                if passed > cli.duration * 1000 {
                    break;
                } else {
                    timeout = cli.duration * 1000 - passed;
                }
            }
        }

        runtime_s = start.elapsed().as_secs();
    }

    let start2 = Instant::now();

    println!("Tracing finished, Processing data...");

    let mut symanalyzer = SymbolAnalyzer::new(None)?;
    process_events(
        &cli,
        &mut skel.maps(),
        &mut result,
        &mut symanalyzer,
        &mut exec_map_hash,
    )?;

    runtime_s += start2.elapsed().as_secs();
    print_result(&cli, &result, runtime_s)?;
    Ok(())
}
