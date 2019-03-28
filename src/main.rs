#![crate_type = "bin"]

extern crate clap;


use std::fs::*;
use std::io::*;
use std::io::BufReader;
use std::time::{SystemTime};
use std::convert;
use std::thread;

use clap::{Arg, App};
use md5::{Md5, Digest};

static DEFAULT_BENCH_VALUE : f64 = 2_000_000.;
static KB : f64 = 1_000.;
static MB : f64 = 1_000_000.;
static GB : f64 = 1_000_000_000.;
static TB : f64 = 1_000_000_000_000.;


fn main() {
    let mut app = Options();
    let matches = app.clone().get_matches();
    let mut filename : String;
    let mut target : String;
    let mut valueHash : String = String::new();
    let mut finded = false;
    let mut HASH = String::new();
    if matches.is_present("BENCH") {
        
        if matches.is_present("METHODS") {
            println!("Methods use  \t: {}", StringMethods(matches.value_of("METHODS").unwrap().parse::<i32>().unwrap()));
        } else {
            println!("Methods use  \t: {}", StringMethods(1));
        }
        let start = SystemTime::now();

        let T = thread::spawn(move||{
            for i in 0..DEFAULT_BENCH_VALUE as u64 {
                
                if matches.is_present("METHODS") {
                    HASH = SwitchHashMethods(i.to_string(),matches.value_of("METHODS").unwrap().parse::<i32>().unwrap());
                } else {
                    HASH = HashMD5(i.to_string());
                } 
                if matches.is_present("VERBOSE") {
                    println!("{} : {}",i,HASH );
                }
            }   
        
        });

        T.join().unwrap();
        

        println!("Time elapsed \t: {}s for {} hash",start.elapsed().unwrap().as_secs(),DEFAULT_BENCH_VALUE);
        let timePass = start.elapsed().unwrap().as_secs();
        if timePass > 0 {
            let mut val = DEFAULT_BENCH_VALUE / timePass as f64;
            let mut result = String::new();
            if val > KB && val < MB {
                let tmp = val / KB;
                result =  format!("{:.3} KH/s",tmp);
            } else if val > MB && val < GB {
                let tmp = val / MB;
                result =  format!("{:.3} MH/s",tmp);        
            } else if val > GB && val < TB {
                let tmp = val / GB;
                result =  format!("{:.3} GH/s",tmp);
            }
            println!("Benchmark \t: {}", result);
        }
        
        

    } else {
        if matches.is_present("FILE") && matches.is_present("TARGET") && matches.is_present("METHODS") {
            let now = SystemTime::now();
            filename = matches.value_of("FILE").unwrap().to_string();
            target = matches.value_of("TARGET").unwrap().to_string();
            println!("wordlist use \t: {}",filename.clone() );
            println!("hash to find \t: {}",target.clone());
            println!("Methods use  \t: {}", StringMethods(matches.value_of("METHODS").unwrap().parse::<i32>().unwrap()));
            println!("===================================");
            let f = File::open(filename).unwrap();
            let mut count : u32 = 0;
            let mut lines = BufReader::new(f).lines();
            for line in lines {
                let mut l = String::new();
                match line {
                    Ok(ll) => {
                        count+=1;
                        l = ll;
                    }
                    Err(err) => {
                        if matches.is_present("VERBOSE") {
                            println!("Error : {}",err);
                        }
                    }
                }
                
                HASH = SwitchHashMethods(l.clone(),matches.value_of("METHODS").unwrap().parse::<i32>().unwrap());

                
                if HASH == target {
                    valueHash = l.clone();
                    finded = true;
                }

                
                if matches.is_present("VERBOSE") {
                    println!("{}  \t:\t  {}",l.clone(),HASH);
                }

                if finded {
                    println!("Hash find : \"{}\"",valueHash.clone() );
                    break;
                } 
            }

            if matches.is_present("COUNT") {
                    println!("Count : {}",count );
            }
            if !finded {
                println!("Hash not found");
            }

            println!("Time : {:?}",now.elapsed().unwrap());

            
        } else {
            app.print_help();
        }
    }
    
}

fn SwitchHashMethods(text : String, method : i32) -> String {
    let mut result = String::new();
    if method == 1 {
        result = HashMD5(text);
    } 
    return result;
}

fn StringMethods(method : i32) -> String {
    let mut result = String::new();
    if method == 1 {
        result = String::from("MD5");
    } else if method == 2 {
        result = String::from("SHA-1");
    } else if method == 3 {
        result = String::from("SHA-256");
    }
    return result;
}


fn HashMD5(text :String) -> String {
    let mut hasher = Md5::new();
    hasher.input(text);
    let tmp = hasher.result();
    let result = format!("{:x}",tmp);
    return result;
}



fn Options<'a>() -> clap::App<'a,'a> {
    let result = App::new("RustHash")
                            .version("0.0.0.1")
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
                                .help("Set methods for hashing : \n1 \t : MD5\n2 \t: SHA-1\n3 \t: SHA-256"))
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
                            .arg(Arg::with_name("HELP")
                                .short("h")
                                .long("help")
                                .required(false)
                                .help("Show this message"));

    return result;

}
