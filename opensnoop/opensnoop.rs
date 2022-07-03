#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    clap::Parser,
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
    std::{
        fmt::Display,
        fs,
        path::{Path, PathBuf},
    },
    tokio::{
        fs::File,
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader},
        signal,
        sync::mpsc::{self, Receiver, Sender},
        sync::oneshot,
        task::JoinHandle,
        time::{timeout, Duration, Instant},
    },
    tracelib::{trace_top_dir, writeln_str_file, Kprobe, TraceLog},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Trace duration in seconds
    #[clap(short = 'd', long = "duration")]
    duration: Option<u64>,

    /// Trace PID
    #[clap(short = 'p', long = "pid")]
    pid: Option<u32>,

    /// Trace COMMAND
    #[clap(short = 'c', long = "command")]
    command: Option<String>,

    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
}

async fn wait_to_finish(start: Instant, duration_s: Option<u64>) -> Result<()> {
    let wait_ctrc = signal::ctrl_c();

    if let Some(s) = duration_s {
        let to = Duration::from_secs(s) - start.elapsed();
        if !to.is_zero() {
            timeout(to, wait_ctrc).await??;
        }
    } else {
        signal::ctrl_c().await?;
    }

    Ok(())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    let max_level = match cli.verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_runtime(false)
        .log_time(false)
        .build();

    let mut duration = None;
    if let Some(d) = cli.duration {
        duration = Some(d);
    }

    if let Some(p) = cli.pid {
        info!("Traing PID {} ...", p);
    }

    if let Some(ref c) = cli.command {
        info!("Traing command {} ...", c);
    }

    let current_tracer = format!("{}/current_tracer", trace_top_dir().await?);

    writeln_str_file(&current_tracer, "nop", false).await?;

    let fns = vec!["do_sys_open"];
    for fname in fns {
        if let Ok(mut kp) = Kprobe::new(None, fname, None) {
            kp.add_arg("file=+0($arg2):string");
            kp.add_arg("flag=+0($arg3):x32");
            kp.add_arg("mode=+0($arg4):x32");
            kp.build().await?;
            kp.enable()
                .await
                .with_context(|| format!("Failed to enable kprobe: {}", kp.group()))?;

            let mut tlog = TraceLog::new().await?;

            println!();
            println!(
                "{:<12} {:15} {:<8} {:<30}",
                "TimeStamp", "Task", "PID", "OpenedFile"
            );
            println!("{}", "=".repeat(80));

            let start = tokio::time::Instant::now();
            loop {
                tokio::select! {
                    //Ok(log) = tlog.trace_print() => print!("{}", log),
                     result = tlog.trace_fields() => {
                         match result {
                            Ok((task, pid, _cpu, _flag, ts, msg)) => {
                                #[allow(clippy::never_loop)]
                                loop {
                                    let mut fname = String::new();
                                    let mut flag = String::new();
                                    let mut mode = String::new();
                                    let mut itor = msg.split(' ').collect::<Vec<&str>>().into_iter();
                                    itor.next();
                                    itor.next();

                                    if let Some(s) = itor.next() {
                                        fname.push_str(s);
                                    } else {
                                        break;
                                    }

                                    if let Some(s) = itor.next() {
                                        flag.push_str(s);
                                    } else {
                                        break;
                                    }

                                    if let Some(s) = itor.next() {
                                        mode.push_str(s);
                                    } else {
                                        break;
                                    }

                                    if let Some(tpid) = cli.pid {
                                        if tpid != pid {
                                            break;
                                        }
                                    }

                                    if let Some(ref c) = cli.command {
                                        if task.len() >= 15 {
                                            if !c.starts_with(&task) {
                                                break;
                                            }
                                        } else if c != &task {
                                                break;
                                        }
                                    }

                                    println!("{:<12} {:15} {:<8} {:<30}",ts, task, pid, fname);
                                    break;
                                }

                            },
                            Err(e) => eprintln!("Error: {}", e),
                         }
                    },
                    _result = wait_to_finish(start, duration) => {
                        let _ = kp.disable();
                        kp.exit().await;
                        break;
                    },

                }
            }

            tlog.terminate().await;

            return Ok(());
        }
    }

    Err(Error::msg("Failed to add a kprobe for execve."))
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        if let Err(e) = async_main().await {
            error!("Error: {}", e);
        }
    });

    rt.shutdown_background();
}
