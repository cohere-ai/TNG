//! usage: nvat-spike-verify <remote|local> <report hex file> <cert chain PEM file> <nonce hex>
//!
//! Prints what `nvat_spike_verify::run` returns; exits 0 on a passing verdict, 1 on a
//! failing one, 3 on an error.

use std::process::ExitCode;

use nvat_spike_verify::run;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: {} <remote|local> <report> <certs> <nonce>", args[0]);
        return ExitCode::from(2);
    }
    match run(&args[1], &args[2], &args[3], &args[4]) {
        Ok(out) => {
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
            if out["success"] == true {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(3)
        }
    }
}
