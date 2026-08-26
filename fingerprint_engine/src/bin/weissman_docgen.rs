//! Offline document generator — the same engines the live API uses.
//!
//! Reads a JSON spec from stdin (or `--in FILE`) and writes PDF or XLSX to stdout
//! (or `--out FILE`). Used by the audit evidence pack and by CI so generated
//! artefacts never drift from product reports.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use fingerprint_engine::pdf::spec::{DocumentSpec, WorkbookSpec};

fn usage() -> ! {
    eprintln!(
        "weissman-docgen — board-grade PDF / XLSX from a JSON spec\n\n\
         Usage:\n  weissman-docgen --pdf  [--in spec.json] [--out out.pdf]\n  \
         weissman-docgen --xlsx [--in spec.json] [--out out.xlsx]\n\n\
         Spec is read from stdin when --in is omitted; bytes go to stdout when --out is omitted."
    );
    std::process::exit(2);
}

fn parse_args() -> (bool, Option<PathBuf>, Option<PathBuf>) {
    let mut kind_xlsx = false;
    let mut kind_pdf = false;
    let mut input = None;
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--pdf" => kind_pdf = true,
            "--xlsx" => kind_xlsx = true,
            "--in" => input = args.next().map(PathBuf::from),
            "--out" => output = args.next().map(PathBuf::from),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }
    if kind_pdf == kind_xlsx {
        eprintln!("specify exactly one of --pdf or --xlsx");
        usage();
    }
    (kind_xlsx, input, output)
}

fn read_spec(path: Option<PathBuf>) -> Result<String, String> {
    if let Some(p) = path {
        fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("stdin: {e}"))?;
        Ok(buf)
    }
}

fn write_out(path: Option<PathBuf>, bytes: &[u8]) -> Result<(), String> {
    if let Some(p) = path {
        fs::write(&p, bytes).map_err(|e| format!("write {}: {e}", p.display()))
    } else {
        io::stdout()
            .write_all(bytes)
            .map_err(|e| format!("stdout: {e}"))
    }
}

fn main() {
    let (xlsx, input, output) = parse_args();
    let raw = match read_spec(input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let bytes = if xlsx {
        match serde_json::from_str::<WorkbookSpec>(&raw) {
            Ok(spec) => match fingerprint_engine::xlsx_report::render_workbook(&spec) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("xlsx: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("invalid workbook spec: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match serde_json::from_str::<DocumentSpec>(&raw) {
            Ok(spec) => match spec.render_pdf() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("pdf: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("invalid document spec: {e}");
                std::process::exit(1);
            }
        }
    };
    if let Err(e) = write_out(output, &bytes) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
