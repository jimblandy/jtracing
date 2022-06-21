#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
    std::{
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

pub struct SymbolAnalyzer {
    kallsyms: Vec<KernelSymbolEntry>,
}

fn addr_str_to_u64(addr_str: &str) -> Result<u64> {
    if let Ok(addr_bytes) = hex::decode(addr_str.trim())?.try_into() {
        Ok(u64::from_be_bytes(addr_bytes))
    } else {
        Err(Error::msg("Invalid address"))
    }
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

        Ok(SymbolAnalyzer { kallsyms })
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
}
