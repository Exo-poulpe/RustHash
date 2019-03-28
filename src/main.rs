#![crate_type = "bin"]

extern crate clap;
mod hardware;

use std::convert;
use std::fs::*;
use std::io::BufReader;
use std::io::*;
use std::time::SystemTime;
use std::thread;

use clap::{App, Arg};
use md5::{Digest, Md5};
use md4::Md4;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use termcolor::*;

static DEFAULT_BENCH_VALUE: f64 = 1_000_000.;
static DEFAULT_SECOND_DIV : f64 = 1_000.;
static KB: f64 = 1_000.;
static MB: f64 = 1_000_000.;
static GB: f64 = 1_000_000_000.;
static TB: f64 = 1_000_000_000_000.;

fn main() {
    let mut app = Options();
    let matches = app.clone().get_matches();
    let mut filename: String;
    let mut target: String;
    let mut valueHash: String = String::new();
    let mut finded = false;
    let mut HASH = String::new();

    // Options hardware
    if matches.is_present("HARDWARE") {
        println!("{}", GetHardInfo());
        std::process::exit(0);
    }

    // Options detect hash
    if matches.is_present("DETECT") {
        println!("Detected  \t: {}", CheckHashValidity(matches.value_of("DETECT").unwrap().to_string()));
        std::process::exit(0);
    }


    // Options BENCH
    if matches.is_present("BENCH") {
        if matches.is_present("METHODS") {
            println!(
                "Methods use  \t: {}",
                StringMethods(matches.value_of("METHODS").unwrap().parse::<i32>().unwrap())
            );
        } else {
            println!("Methods use  \t: {}", StringMethods(1));
        }
        println!("Hash number \t: {}", DEFAULT_BENCH_VALUE);
        println!("===================================");
        let start = SystemTime::now();

        let T = thread::spawn(move || {
            for i in 0..DEFAULT_BENCH_VALUE as u64 {
                if matches.is_present("METHODS") {
                    HASH = SwitchHashMethods(
                        i.to_string(),
                        matches.value_of("METHODS").unwrap().parse::<i32>().unwrap(),
                    );
                } else {
                    HASH = HashMD5(i.to_string());
                }
                if matches.is_present("VERBOSE") {
                    println!("{} : {}", i, HASH);
                }
            }
        });

        T.join().unwrap();

        println!("Time elapsed \t: {:.2}s", start.elapsed().unwrap().as_millis() as f64 / DEFAULT_SECOND_DIV as f64 );

        let diff = start.elapsed().unwrap().as_millis() as f64;
        // Calc benchmark
        let timePass = diff / DEFAULT_SECOND_DIV as f64;
        if timePass > 0.0 {
            let mut val = DEFAULT_BENCH_VALUE / timePass as f64;
            let mut result = String::new();
            if val > KB && val < MB {
                let tmp = val / KB;
                result = format!("{:.3} KH/s", tmp);
            } else if val > MB && val < GB {
                let tmp = val / MB;
                result = format!("{:.3} MH/s", tmp);
            } else if val > GB && val < TB {
                let tmp = val / GB;
                result = format!("{:.3} GH/s", tmp);
            }
            println!("Benchmark \t: {}", result);
        }
    } else {
        // If program start normaly
        if matches.is_present("FILE")
            && matches.is_present("TARGET")
            && matches.is_present("METHODS")
        {
            let start = SystemTime::now();
            filename = matches.value_of("FILE").unwrap().to_string();
            target = matches.value_of("TARGET").unwrap().to_string();
            if matches.is_present("VERBOSE") {
                println!("CPU : {}\nMemory : {}", GetCpuInfo(), GetMemInfo());
            }
            println!("wordlist use \t: {}", filename.clone());
            println!("hash to find \t: {}", target.clone());
            println!(
                "Methods use  \t: {}",
                StringMethods(matches.value_of("METHODS").unwrap().parse::<i32>().unwrap())
            );
            println!("===================================");
            let f = File::open(filename).unwrap();
            let mut count: u32 = 0;
            let mut lines = BufReader::new(f).lines();

            for line in lines {
                
                

                    let mut l = String::new();
                    match line {
                        Ok(ll) => {
                            count += 1;
                            l = ll;
                        }
                        Err(err) => {
                            if matches.is_present("VERBOSE") {
                                println!("Error : {}", err);
                            }
                        }
                    }
                    HASH = SwitchHashMethods(l.clone(),matches.value_of("METHODS").unwrap().parse::<i32>().unwrap());

                    if HASH == target {
                        valueHash = l.clone();
                        finded = true;
                    }

                    if matches.is_present("VERBOSE") {
                        println!("{}    \t: {}", l.clone(), HASH);
                    }
                    
                    

                if finded {
                    let mut stdout = StandardStream::stdout(ColorChoice::Always);
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
                    writeln!(&mut stdout,"Hash found : \"{}\"", valueHash.clone());
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)));
                    //println!("Hash found : \"{}\"", valueHash.clone());
                    break;
                }
            }

            if matches.is_present("COUNT") {
                println!("Count \t\t: {}", count);
            }
            if !finded {
                let mut stdout = StandardStream::stdout(ColorChoice::Always);
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)));
                writeln!(&mut stdout,"Hash not found");
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)));
                //println!("Hash not found");
            }
            println!("Time elapsed : {:.2}s", start.elapsed().unwrap().as_millis() as f64 / DEFAULT_SECOND_DIV as f64 );
        } else {
            app.print_help();
        }
    }
}

fn SwitchHashMethods(text: String, method: i32) -> String {
    let mut result = String::new();
    match method {
        1 => result = HashMD5(text),
        2 => result = HashMD4(text),
        3 => result = HashSHA1(text),
        4 => result = HashSHA256(text),
        5 => result = HashSHA512(text),
        _ => result = HashMD5(text),
    }
    return result;
}

fn StringMethods(method: i32) -> String {
    let mut result = String::new();
    match method {
        1 => result = String::from("MD5"),
        2 => result = String::from("MD4"),
        3 => result = String::from("SHA-1"),
        4 => result = String::from("SHA-256"),
        5 => result = String::from("SHA-512"),
        _ => result = String::from("MD5"),
    }
    return result;
}

fn HashMD5(text: String) -> String {
    let mut hasher = Md5::new();
    hasher.input(text);
    let tmp = hasher.result();
    let result = format!("{:x}", tmp);
    return result;
}

fn HashSHA1(text: String) -> String {
    let mut hasher = Sha1::new();
    hasher.input(text);
    let tmp = hasher.result();
    let result = format!("{:x}", tmp);
    return result;
}

fn HashSHA256(text: String) -> String {
    let mut hasher = Sha256::new();
    hasher.input(text);
    let tmp = hasher.result();
    let result = format!("{:x}", tmp);
    return result;
}

fn HashSHA512(text: String) -> String {
    let mut hasher = Sha512::new();
    hasher.input(text);
    let tmp = hasher.result();
    let result = format!("{:x}", tmp);
    return result;
}

fn HashMD4(text : String) -> String {
    let mut hasher = Md4::new();
    hasher.input(text);
    let tmp = hasher.result();
    let result = format!("{:x}", tmp);
    return result;
}

fn CheckHashValidity(hash : String) -> String {
    let mut result = String::from("MD5");
    match hash.len() {
        32 => result = String::from("MD5 / MD4"),
        40 => result = String::from("SHA-1"),
        64 => result = String::from("SHA-256"),
        128 => result = String::from("SHA-512"),
        _ => result = String::from("Detect failed"),
    }

    return result;
}

fn GetCpuInfo() -> String {
    let info: hardware::SysInfo = hardware::SysInfo::new();
    return info.cpu.brand;
}

fn GetMemInfo() -> String {
    let info: hardware::SysInfo = hardware::SysInfo::new();
    let result = format!(
        "{:.2} GB / {:.2} GB",
        info.mem.free as f64 / MB,
        info.mem.total as f64 / MB
    );
    return result;
}

fn GetHardInfo() -> String {
    let info: hardware::SysInfo = hardware::SysInfo::new();
    let cpu = &info.cpu;
    let mem = &info.mem;
    let os = &info.os;
    let result = format!("CPU  \t\t: {}\nCPU cores \t: {}\nMemory   \t: {:.2} GB / {:.2} GB\nOS   \t\t: {}\nOS version \t: {}",cpu.brand,cpu.cores,
     mem.free as f64 / MB,mem.total as f64 / MB,os.name,os.version);
    return result;
}

fn Options<'a>() -> clap::App<'a, 'a> {
    let result = App::new("RustHash")
                            .version("0.0.2.5")
                            .author("Exo-poulpe")
                            .about("Rust hash test hash from wordlist")
                            .arg(Arg::with_name("FILE")
                                .short("f")
                                .long("file")
                                .required(false)
                                .takes_value(true)
                                .help("Set wordlist to use"))
                            .arg(Arg::with_name("METHODS")
                                .short("m")
                                .required(false)
                                .takes_value(true)
                                .help("Set methods for hashing : \n1) \t: MD5\n2) \t: MD4\n3) \t: SHA-1\n4) \t: SHA-256\n5) \t: SHA-512"))
                            .arg(Arg::with_name("TARGET")
                                .short("t")
                                .long("target")
                                .required(false)
                                .takes_value(true)
                                .help("Set hash target for test"))
                            .arg(Arg::with_name("DETECT")
                                .long("detect-hash")
                                .required(false)
                                .takes_value(true)
                                .help("Check if hash is valid"))
                            .arg(Arg::with_name("VERBOSE")
                                .short("v")
                                .long("verbose")
                                .required(false)
                                .help("More verbose output"))
                            .arg(Arg::with_name("COUNT")
                                .short("c")
                                .required(false)
                                .help("Show number of password tested"))
                            .arg(Arg::with_name("BENCH")
                                .short("b")
                                .long("benchmark")
                                .required(false)
                                .help("Test hash perfs"))
                            .arg(Arg::with_name("HARDWARE")
                                .long("hardware-info")
                                .required(false)
                                .help("Show info hardware"))                                
                            .arg(Arg::with_name("HELP")
                                .short("h")
                                .long("help")
                                .required(false)
                                .help("Show this message"));

    return result;
}
