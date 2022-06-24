use object::{Object, ObjectSymbol};

#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
    regex::Regex,
    std::{
        collections::HashMap,
        fmt::Display,
        fs,
        io::{BufRead, BufReader},
        path::{Path, PathBuf},
    },
};

#[derive(Clone, Copy)]
pub enum NmSymbolType {
    Absolute,
    BssData,
    CommonSymbol,
    InitializedData,
    InitializedSmallData,
    IndirectFunction,
    IndirectRef,
    DebugSymbol,
    ReadOnlyN,
    StackUnwind,
    ReadOnlyR,
    UnInitializedData,
    Text,
    Undefined,
    UniqueGlobalSymbol,
    WeakObjectV,
    WeakObjectW,
    StabsSymbol,
    Unknown,
}

pub struct KernelSymbolEntry {
    addr: u64,
    ktype: NmSymbolType,
    name: String,
    module: String,
    len: u64,
}

pub enum Symbol {
    Symbol(String),
    TooSmall,
    TooLarge,
}

impl KernelSymbolEntry {
    pub fn set_len(&mut self, len: u64) {
        self.len = len;
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn ktype(&self) -> NmSymbolType {
        self.ktype
    }

    pub fn module(&self) -> &str {
        self.module.as_str()
    }

    pub fn symbol(&self, addr: u64) -> Symbol {
        if addr < self.addr {
            Symbol::TooSmall
        } else if addr >= self.addr + self.len {
            Symbol::TooLarge
        } else if addr == self.addr {
            Symbol::Symbol(self.name.clone())
        } else {
            Symbol::Symbol(format!("{}+0x{:x}", self.name, addr - self.addr))
        }
    }
}

pub struct MapTextEntry {
    pub start: u64,
    pub end: u64,
    pub file: String,
}

impl MapTextEntry {
    pub fn have(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

pub struct ExecMap {
    entries: Vec<MapTextEntry>,
    pid: u32,
}

impl ExecMap {
    pub fn new(pid: u32) -> Result<Self> {
        let mapf = fs::OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/maps", pid))?;
        let mut reader = BufReader::new(mapf);
        let mut entries = Vec::new();
        // match something like 
        // 7fadf15000-7fadf1c000 r-xp 00000000 b3:02 12147                          /usr/lib/libipcon.so.0.0.0
        let re = Regex::new(
            r"^([0-9|a-f]+)-([0-9|a-f]+) r\-xp ([0-9|a-f]+ [0-9|a-f|:]+ [0-9]+ +)(/[a-z|A-Z|0-9|\.|\-|_|/]+)\n$",
        )?;

        loop {
            let mut l = String::new();

            let len = reader.read_line(&mut l)?;
            if len == 0 {
                break;
            }

            for g in re.captures_iter(&l) {
                let start = addr_str_to_u64(&g[1])?;
                let end = addr_str_to_u64(&g[2])?;
                let file = &g[4].trim_end_matches('\n').trim().to_string();

                entries.push(MapTextEntry {
                    start,
                    end,
                    file: file.trim_end_matches('\n').trim().to_string(),
                });
            }
        }

        Ok(ExecMap { entries, pid })
    }

    pub fn symbol(&self, addr: u64) -> Result<(String, String)> {
        let mut keys = String::new();

        for entry in &self.entries {
            keys.push_str(&format!(" {:x}:{:x}", entry.start, entry.end));
            if entry.have(addr) {
                let file = fs::File::open(&entry.file)?;
                let map = unsafe { memmap::Mmap::map(&file)? };
                let object = object::File::parse(&map[..])?;
                let syms = object.symbols();
                let dynsyms = object.dynamic_symbols();
                let offset = addr - entry.start;
                let symname = String::from(format!("?@0x{:x}", offset));

                for sym in syms {
                    let start = sym.address();
                    let size = sym.size();

                    if offset >= start && offset < start + size {
                        if let Ok(s) = sym.name() {
                            let sym_str = {
                                if offset == start {
                                    format!("{}", s)
                                } else {
                                    format!("{}+{}", s, offset - start)
                                }
                            };
                            return Ok((sym_str, entry.file.clone()));
                        }
                    }
                }

                for sym in dynsyms {
                    let start = sym.address();
                    let size = sym.size();

                    if offset >= start && offset < start + size {
                        if let Ok(s) = sym.name() {
                            let sym_str = {
                                if offset == start {
                                    format!("{}", s)
                                } else {
                                    format!("{}+{}", s, offset - start)
                                }
                            };
                            return Ok((sym_str, entry.file.clone()));
                        }
                    }
                }

                return Ok((symname, entry.file.clone()));
            }
        }

        return Err(Error::msg(format!(
            "Invalid addr {:x} for pid {}. Avaliable key: {}",
            addr, self.pid, keys
        )));
    }
}

pub struct SymbolAnalyzer {
    kallsyms: Vec<KernelSymbolEntry>,
    map: HashMap<u32, ExecMap>,
}

pub fn addr_str_to_u64(addr_str: &str) -> Result<u64> {
    let mut u8array: [u8; 8] = [0; 8];
    let mut fixed_str = String::from(addr_str.trim());

    if fixed_str.len() % 2 != 0 {
        fixed_str = format!("0{}", fixed_str);
    }

    let bytes = hex::decode(&fixed_str)?;

    if bytes.len() > 8 {
        return Err(Error::msg(format!(
            "Invalid address {} bytes len: {}",
            addr_str,
            bytes.len()
        )));
    }

    u8array[8 - bytes.len()..].clone_from_slice(&bytes[..]);

    Ok(u64::from_be_bytes(u8array))
}

impl SymbolAnalyzer {
    pub fn new(symbolfile: Option<&str>) -> Result<Self> {
        let f = if let Some(sf) = symbolfile {
            fs::OpenOptions::new().read(true).open(sf)?
        } else {
            fs::OpenOptions::new().read(true).open("/proc/kallsyms")?
        };

        let mut reader = BufReader::new(f);
        let mut kallsyms: Vec<KernelSymbolEntry> = Vec::new();

        loop {
            let mut line = String::new();

            match reader.read_line(&mut line) {
                Ok(a) if a != 0 => (),
                _ => break,
            }

            let mut entries = line.split(' ').into_iter();

            let addr_str = entries
                .next()
                .ok_or_else(|| Error::msg("Invalid data"))?
                .trim();
            let addr = addr_str_to_u64(addr_str)?;

            let t = entries
                .next()
                .ok_or_else(|| Error::msg("Invalid data"))?
                .trim();
            let ktype = match t {
                "A" | "a" => NmSymbolType::Absolute,
                "B" | "b" => NmSymbolType::BssData,
                "C" => NmSymbolType::CommonSymbol,
                "D" | "d" => NmSymbolType::InitializedData,
                "G" | "g" => NmSymbolType::InitializedSmallData,
                "i" => NmSymbolType::IndirectFunction,
                "I" => NmSymbolType::IndirectRef,
                "N" => NmSymbolType::DebugSymbol,
                "n" => NmSymbolType::ReadOnlyN,
                "p" => NmSymbolType::StackUnwind,
                "R" | "r" => NmSymbolType::ReadOnlyR,
                "S" | "s" => NmSymbolType::UnInitializedData,
                "T" | "t" => NmSymbolType::Text,
                "U" => NmSymbolType::Undefined,
                "u" => NmSymbolType::UniqueGlobalSymbol,
                "V" | "v" => NmSymbolType::WeakObjectV,
                "W" | "w" => NmSymbolType::WeakObjectW,
                "-" => NmSymbolType::StabsSymbol,
                "?" => NmSymbolType::Unknown,
                _ => return Err(Error::msg("Invalid data")),
            };

            let name = String::from(
                entries
                    .next()
                    .ok_or_else(|| Error::msg("Invalid data"))?
                    .trim(),
            );

            let mut module = String::new();
            if let Some(m) = entries.next() {
                module.push_str(m);
            }

            kallsyms.push(KernelSymbolEntry {
                addr,
                ktype,
                name,
                module,
                len: u64::max_value(),
            });
        }

        /* Descending order */
        kallsyms.sort_by(|a, b| b.addr().partial_cmp(&a.addr()).unwrap());

        let mut addr = u64::max_value();
        for i in 0..kallsyms.len() {
            let v = &mut kallsyms[i];
            if addr >= v.addr() {
                v.set_len(addr - v.addr())
            }

            addr = v.addr();
        }

        Ok(SymbolAnalyzer {
            kallsyms,
            map: HashMap::new(),
        })
    }

    pub fn ksymbol_str(&self, addr_str: &str) -> Result<String> {
        let addr = addr_str_to_u64(addr_str)?;
        self.ksymbol(addr)
    }

    pub fn ksymbol(&self, addr: u64) -> Result<String> {
        let search_symbol =
            |v: &Vec<KernelSymbolEntry>, start: usize, end: usize, addr: u64| -> Symbol {
                let mut start = start;
                let mut end = end;
                loop {
                    if start == end {
                        return v[start].symbol(addr);
                    }

                    let i = (end - start) / 2 + start;
                    match v[i].symbol(addr) {
                        Symbol::Symbol(s) => return Symbol::Symbol(s),
                        Symbol::TooSmall => start = i,
                        Symbol::TooLarge => end = i,
                    }
                }
            };

        match search_symbol(&self.kallsyms, 0, self.kallsyms.len(), addr) {
            Symbol::Symbol(s) => Ok(s),
            _ => Err(Error::msg("Invalid addr")),
        }
    }

    pub fn usymbol(&mut self, pid: u32, addr: u64) -> Result<(String, String)> {
        let em = self.map.entry(pid).or_insert(ExecMap::new(pid)?);
        em.symbol(addr)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn new() {
        use crate::symbolanalyzer::SymbolAnalyzer;
        let sa = SymbolAnalyzer::new(Some("testfiles/test_symbol")).unwrap();

        let sym = sa.ksymbol_str("ffffffffb731c4f0").unwrap();
        assert_eq!(sym, "do_sys_open");
    }

    #[test]
    fn addr_str_to_u64_test() {
        use crate::symbolanalyzer::addr_str_to_u64;
        assert_eq!(addr_str_to_u64("0").unwrap(), 0_u64);
        assert_eq!(addr_str_to_u64("f").unwrap(), 15_u64);
        assert_eq!(addr_str_to_u64("7f8d66a000").unwrap(), 547833159680_u64);
        assert_eq!(
            addr_str_to_u64("000000558e510590").unwrap(),
            367459894672_u64
        );
        assert_eq!(addr_str_to_u64("ffffffffffffffff").unwrap(), u64::MAX);
    }
}
