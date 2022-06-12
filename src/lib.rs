#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
    std::{
        fmt::Display,
        path::{Path, PathBuf},
    },
    tokio::{
        fs::{self, File},
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
    },
};

pub mod kprobe;
pub mod tracelog;

pub use kprobe::Kprobe;
pub use tracelog::TraceLog;

pub fn writeln_proc(f: &str, s: &str, append: bool) -> Result<()> {
    use std::ffi::CString;

    unsafe {
        let cfile = CString::new(f)?;
        let mut mode = CString::new("w")?;
        if append {
            mode = CString::new("a")?;
        }
        let fp = libc::fopen(cfile.as_ptr(), mode.as_ptr());

        if fp.is_null() {
            return Err(Error::msg(format!("Failed to open {}", f)));
        }

        let cbuf = CString::new(s)?;
        let ret = libc::fwrite(
            cbuf.as_ptr() as *const libc::c_void,
            cbuf.as_bytes().len(),
            1,
            fp,
        ) as i32;

        if ret < 0 {
            return Err(Error::msg(format!("Failed to write {}", f)));
        }
    }
    Ok(())
}

pub async fn writeln_str_file(f: &str, s: &str, append: bool) -> Result<()> {
    let fp = Path::new(f);

    if !fp.is_file() {
        return Err(Error::msg(format!("File {} not exist.", f)));
    }

    let file = fs::OpenOptions::new()
        .write(true)
        .append(append)
        .open(fp)
        .await
        .with_context(|| format!("Failed to open {}", f))?;

    let mut ns = String::from(s);
    if !ns.ends_with('\n') {
        ns.push('\n')
    }

    if ns == "\n" {
        return writeln_proc(f, s, append);
    }

    let mut writer = BufWriter::new(file);

    writer
        .write(ns.as_bytes())
        .await
        .with_context(|| format!("Failed write {} to {}", ns, f))?;

    writer
        .flush()
        .await
        .with_context(|| format!("Failed write {} to {}", ns, f))?;

    Ok(())
}

pub async fn trace_top_dir() -> Result<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .open(Path::new("/proc/mounts"))
        .await?;

    let mut lines = BufReader::new(file).lines();

    while let Some(l) = &lines.next_line().await? {
        let entries: Vec<&str> = l.split(' ').collect();
        if entries[0] != "debugfs" {
            continue;
        }

        let mut tracing_dir = String::from(entries[1]);
        tracing_dir.push_str("/tracing");

        return Ok(tracing_dir);
    }

    Err(Error::msg("trace_pipe not found"))
}
