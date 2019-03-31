#![crate_type = "bin"]

extern crate clap;
mod hardware;

use std::convert;
use std::fs::*;
use std::io::BufReader;
use std::io::*;
use std::vec::*;
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
    let mut target: Vec<String> ;
    let mut valueHash = String::new();
    let mut finded = false;
    let mut HASH = String::new();
    let mut count: u32 = 0;

    // Options hardware
    if matches.is_present("HARDWARE") {
        println!("{}", GetHardInfo());
        std::process::exit(0);
    }

    // Options detect hash
    if matches.is_present("DETECT") {
        let hashToDetect : Vec<String> = TargetIsFile(matches.value_of("DETECT").expect("Fail to unwrap").to_string());
        let detected : Vec<String> = CheckHashValidity(hashToDetect.clone());
        for i in 0..hashToDetect.len() {
            println!("Hash \t: {}  detect \t: {}",hashToDetect[i].clone(),detected[i].clone() );
        }
        std::process::exit(0);
    }


    // Options BENCH
    if matches.is_present("BENCH") {
        println!("CPU : {}",GetCpuInfo() );
        if matches.is_present("METHODS") {
            println!("Methods use  \t: {}",StringMethods(matches.value_of("METHODS").expect("Fail to get value of flag").parse::<i32>().expect("Fail to parse value of flag")));
        } else {
            println!("Methods use  \t: {}", StringMethods(1));
        }
        println!("Hash number \t: {}", DEFAULT_BENCH_VALUE);
        println!("{:=<1$}", "", 35);
        let start = SystemTime::now();
        
            for i in 0..DEFAULT_BENCH_VALUE as u64{
                if matches.is_present("METHODS") {
                    HASH = SwitchHashMethods(
                        i.to_string(),
                        matches.value_of("METHODS").expect("Fail to get value of flag").parse::<i32>().expect("Fail to parse value of flag"));
                } else {
                    HASH = HashMD5(i.to_string());
                }

                if matches.is_present("VERBOSE") {
                    println!("{} : {}", i, HASH);
                }
            }
        
        println!("Time elapsed \t: {:.2}s", start.elapsed().expect("Fail to get value of time").as_millis() as f64 / DEFAULT_SECOND_DIV as f64 );

        let diff = start.elapsed().expect("Fail to get value of time").as_millis() as f64;
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
            println!("Benchmark \t: ~{}", result);
        }
    } 
    else //////////////////////////////////////////////////////////////////////////////
    {
        if matches.is_present("FILE") && matches.is_present("GENERATE_POTFILENAME") && matches.is_present("METHODS") {
                let path : String = matches.value_of("FILE").expect("Fail to read file options").to_string();
                let potfile : String = matches.value_of("GENERATE_POTFILENAME").expect("Fail to use custom path for potfile").to_string();
                let m : i32 = matches.value_of("METHODS").expect("Fail to get value of flag").parse::<i32>().expect("Fail to parse flag value");
                println!("Start to generate using : {} ",path);
                println!("Hash use \t: {}", StringMethods(m.clone()));
                println!("{:=<1$}", "", 35);
                GeneratePotFile(path.clone(), potfile.clone(), m.clone());
                std::process::exit(0);
        }


        // If program start normaly
        if matches.is_present("FILE") && matches.is_present("TARGET") && matches.is_present("METHODS")
        {
            let start = SystemTime::now();

            filename = matches.value_of("FILE").expect("Fail to get value of flag").to_string();
            target = TargetIsFile(matches.value_of("TARGET").expect("Fail to get value of flag").to_string());        

            if matches.is_present("VERBOSE") 
            {
                println!("CPU : {}\nMemory : {}", GetCpuInfo(), GetMemInfo());
            }

            println!("wordlist use \t: {}", filename.clone());

            if target.len() == 1 
            {
                println!("hash to find \t: {}", target.clone()[0]);
            } 
            else 
            {
                println!("file hashes \t: {}", matches.value_of("TARGET").expect("Fail to get value of flag").to_string() );
            }
            println!("Methods use  \t: {}",StringMethods(matches.value_of("METHODS").expect("Fail to get value of flag").parse::<i32>().expect("Fail to parse flag value")));
            println!("{:=<1$}", "", 35);

            // For each string in array
            for HashLine in target.clone() {

                    finded = false;

                    // Disable potfile checking
                    if !matches.is_present("DISABLE_POTFILE") {
                    let mut ret : String;
                        if matches.is_present("PATH_POTFILE") {
                            ret = CheckPotFile(HashLine.clone(),matches.value_of("PATH_POTFILE").expect("Fail to get potfile value").to_string());
                        } else {
                            ret = CheckPotFile(HashLine.clone(),"".to_string());
                        }
                    if ret != "" {
                        let mut result = format!("Hash found \t: \"{}\":{}",HashLine.clone(), ret);
                        if target.len() == 1 
                        {
                            PrintColor(result, Color::Green);
                        } else 
                        {
                            result = format!("Hash found \t: \"{}\":{}", HashLine.clone(),ret);
                            PrintColor(result, Color::Green);
                        }
                        finded = true;
                    }
                }


                // if password is not in potfile
                if !finded 
                {
                
                let f = File::open(filename.clone()).expect("Fail to open file");
                let mut lines = BufReader::new(f).lines();
                count = 0;

                // Read file line by line
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
                        HASH = SwitchHashMethods(l.clone(),matches.value_of("METHODS").expect("Fail to get value of flag").parse::<i32>().expect("Fail to parse value of flag"));

                        if HASH == HashLine.clone() {
                            valueHash = l.clone();
                            finded = true;
                        }

                        if matches.is_present("VERBOSE") {
                            println!("{}    \t: {}", l.clone(), HASH.clone());
                        }
                        
                        

                    if finded {
                        let result = format!("Hash found \t: \"{}\":{}", HashLine.clone(),valueHash.clone());
                        PrintColor(result, Color::Green);
                        if !matches.is_present("DISABLE_POTFILE") {
                            AddToPotFile(HashLine.clone(),valueHash.clone(),"".to_string());
                        }

                    }                        

                }

                }

                


                if !finded {
                    PrintColor("Hash not found".to_string(), Color::Red);
                }
                if matches.is_present("COUNT") {
                    println!("Count \t\t: {}", count);
                    count = 0;
                }

            }

            println!("Time elapsed \t: {:.2}s", start.elapsed().expect("Fail to get time value").as_millis() as f64 / DEFAULT_SECOND_DIV as f64 );
        } else {
            app.print_help();
        }
    }
}

// HASH func
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

fn CheckHashValidity(hashes : Vec<String>) -> Vec<String> {

    let mut result : Vec<String> = Vec::new();
    
    for hash in hashes {
    match hash.len() {
        32 => result.push(String::from("MD5 / MD4")),
        40 => result.push(String::from("SHA-1")),
        64 => result.push(String::from("SHA-256")),
        128 => result.push(String::from("SHA-512")),
        _ => result.push(String::from("Detect failed")),
    }
    }
    return result;
}
/////////////////////





// POTFILE func
fn CheckPotFile(hash : String,filePath : String) -> String
{
    let mut result = String::from("");
    let fileResult : String;
    if filePath != "" {
        fileResult = filePath;
    } else {
        fileResult = String::from("rusthash.pot");
    }
    match File::open(fileResult) {
        Ok(f) => {
            let lines = BufReader::new(f).lines();
            for line in lines {

                match line {
                        Ok(ll) => {
                            let potHash : Vec<&str> = ll.split(":").collect();
                            if potHash[0] == hash {
                                result = potHash[1].to_string(); 
                                break;
                            }
                        }
                        Err(_) => {}
                    }
            }
        }
        _ => {
            let potFile = File::create("rusthash.pot").expect("File not create");
        }

    }
        return result;
}

fn AddToPotFile(hash : String,text : String,potFileName :String) {
    let mut file;
    if potFileName != "".to_string() {
        file = OpenOptions::new()
        .write(true).append(true).open(potFileName).expect("Fail to open pot file");
    } else {
        file = OpenOptions::new()
        .write(true).append(true).open("rusthash.pot").expect("Fail to open (default) pot file");
    }

    let result = format!("{}:{}",hash,text);

    if let Err(e) = writeln!(file, "{}" ,result) {
        eprintln!("Couldn't write to pot file: {}", e);
    }
}

fn GeneratePotFile(wordlist : String,filename : String,method : i32) {
    if filename != "".to_string() {
        File::create(filename.clone()).expect("Fail to create file");
    }
    
    let f = File::open(wordlist.clone()).expect("Fail to open file");
    let lines = BufReader::new(&f).lines();
    let mut HASH = String::new();
    let mut count : u32 = 0;

    for line in lines {
        match line {
            Ok(l) => {
                HASH = SwitchHashMethods(l.clone(),method.clone());
                AddToPotFile(HASH,l.clone(),filename.clone());
                count+=1;
            }
            Err(e) => {
                eprintln!("Fail to read line for potfile {}",e);
            }
        }
    }
    println!("Total password \t: {}",count );
    
}

/////////////////////



// HARDWARE func
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
/////////////////////


// MISC
fn PrintColor(text : String, c : Color) {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        stdout.set_color(ColorSpec::new().set_fg(Some(c)));
        writeln!(&mut stdout,"{}",text);
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)));
}

fn TargetIsFile(option : String) -> Vec<String> {
    let mut result : Vec<String> = Vec::new();
    match File::open(option.clone()) {
        Ok(f) => {
            let lines = BufReader::new(f).lines();
            for line in lines {
                match line {
                    Ok(l) => {
                        result.push(l.to_lowercase());
                    }
                    _ => {}
                }
            }
        }
        Err(_) => {
            result.push(option.clone().to_lowercase());
        }
    }

    return result;    
}
/////////////////////




// OPTIONS parser
fn Options<'a>() -> clap::App<'a, 'a> {
    let result = App::new("RustHash")
                            .version("0.0.3.3")
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
                                .help("Set hashes to test (file or string)"))
                            .arg(Arg::with_name("DETECT")
                                .long("detect-hash")
                                .required(false)
                                .takes_value(true)
                                .help("Check if hash is valid"))
                            .arg(Arg::with_name("VERBOSE")
                                .short("v")
                                .long("verbose")
                                .required(false)
                                .help("More verbose output (slower)"))
                            .arg(Arg::with_name("DISABLE_POTFILE")
                                .long("disable-potfile")
                                .required(false)
                                .help("Disable potfile check"))
                            .arg(Arg::with_name("PATH_POTFILE")
                                .long("path-potfile")
                                .required(false)
                                .takes_value(true)
                                .help("Choose potfile to use"))
                            .arg(Arg::with_name("GENERATE_POTFILENAME")
                                .long("generate-potfile")
                                .required(false)
                                .takes_value(true)
                                .help("Generate a potfile (slower)"))
                            .arg(Arg::with_name("COUNT")
                                .short("c")
                                .required(false)
                                .help("Print number of password tested (slower)"))
                            .arg(Arg::with_name("BENCH")
                                .short("b")
                                .long("benchmark")
                                .required(false)
                                .help("Test hash perfs"))
                            .arg(Arg::with_name("HARDWARE")
                                .long("hardware-info")
                                .required(false)
                                .help("Print info hardware"))                                
                            .arg(Arg::with_name("HELP")
                                .short("h")
                                .long("help")
                                .required(false)
                                .help("Print this message"));

    return result;
}
/////////////////////
