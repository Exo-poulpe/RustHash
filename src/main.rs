#![crate_type = "bin"]

extern crate clap;


use std::fs::*;
use std::io::*;
use std::io::BufReader;
use std::str;
use std::time::{Duration, SystemTime};
use std::io::prelude::*;

use clap::{Arg, App, SubCommand};
use md5::{Md5, Digest};

static FILENAME : &str = "";


fn main() {
    let mut app = Options();
    let matches = app.clone().get_matches();
    let mut filename : String;
    let mut target : String;
    let mut valueHash : String = String::new();
    let mut finded = false;
    if matches.is_present("BENCH") {
        
    } else {
        if matches.is_present("FILE") && matches.is_present("TARGET") && matches.is_present("METHODS") {
            let now = SystemTime::now();
            filename = matches.value_of("FILE").unwrap().to_string();
            target = matches.value_of("TARGET").unwrap().to_string();
            println!("wordlist use \t: {}",filename.clone() );
            println!("hash to find \t: {}",target.clone());
            println!("===================================");
            let f = File::open(filename).unwrap();
            let mut count : u32 = 0;
            let mut lines = BufReader::new(f).lines();
            let mut HASH = String::new();
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
