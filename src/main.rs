#![crate_type = "bin"]

extern crate clap;
extern crate time;
mod hardware;

use std::convert;
use std::fs::*;
use std::io::BufReader;
use std::io::*;
use std::thread;

use clap::{App, Arg};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use termcolor::*;

static DEFAULT_BENCH_VALUE: f64 = 1_000_000.;
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
    if matches.is_present("HARDWARE") {
        println!("{}", GetHardInfo());
        std::process::exit(0);
    }
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
        let start = String::from(time::now().rfc822().to_string());
        let startTime = time::now().tm_nsec as f64 / 1000 as f64;

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

        let stop = String::from(time::now().rfc822().to_string());
        println!("Start : {}", start );
        println!("Stop  : {}", stop );

        // Calc benchmark
        let timePass = startTime as f64 / 1000 as f64;
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
        if matches.is_present("FILE")
            && matches.is_present("TARGET")
            && matches.is_present("METHODS")
        {
            let start = String::from(time::now().rfc822().to_string());
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
                println!("Count : {}", count);
            }
            if !finded {
                let mut stdout = StandardStream::stdout(ColorChoice::Always);
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)));
                writeln!(&mut stdout,"Hash not found");
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)));
                //println!("Hash not found");
            }
            let stop = String::from(time::now().rfc822().to_string());
            println!("Started : {}", start );
            println!("Stopped : {}", stop );
        } else {
            app.print_help();
        }
    }
}

fn SwitchHashMethods(text: String, method: i32) -> String {
    let mut result = String::new();
    match method {
        1 => result = HashMD5(text),
        2 => result = HashSHA1(text),
        3 => result = HashSHA256(text),
        4 => result = HashSHA512(text),
        _ => result = HashMD5(text),
    }
    return result;
}

fn StringMethods(method: i32) -> String {
    let mut result = String::new();
    match method {
        1 => result = String::from("MD5"),
        2 => result = String::from("SHA-1"),
        3 => result = String::from("SHA-256"),
        4 => result = String::from("SHA-512"),
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
                            .version("0.0.2.1")
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
                                .help("Set methods for hashing : \n1) \t: MD5\n2) \t: SHA-1\n3) \t: SHA-256\n4) \t: SHA-512"))
                            .arg(Arg::with_name("TARGET")
                                .short("t")
                                .long("target")
                                .required(false)
                                .takes_value(true)
                                .help("Set hash target for test"))
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
