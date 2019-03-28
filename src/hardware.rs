extern crate sys_info;  // Memory info + os info
extern crate raw_cpuid; // Cpu info

use std::convert::*;
use std::mem;
use std::string::String;

use sys_info::*;
use raw_cpuid::CpuId;



static GB : f32 = 1000000.;


pub struct CPU {
    pub brand: String,
    pub cores: i32,
}
pub struct MEM {
    pub total:f32,
    pub free:f32,
}
pub struct OS {
    pub name: String,
    pub version: String,
}
pub struct SysInfo {
    pub cpu: CPU,
    pub mem: MEM,
    pub os: OS,
}
impl SysInfo {
    pub fn new() -> SysInfo {
        // CPU
        let cpuid = CpuId::new();
        let Strcores = sys_info::cpu_num().unwrap();
        let tmp = cpuid.get_extended_function_info().unwrap();
        let Strbrand = tmp.processor_brand_string().unwrap();

        // MEM
        let mem = sys_info::mem_info().unwrap();

        // OS
        let os_name = sys_info::os_type().unwrap();
        let os_version = sys_info::os_release().unwrap();

        return SysInfo { 
            cpu:CPU{brand:String::from(Strbrand),cores:(Strcores as i32)},
            mem:MEM{total:(mem.total as f32),free:(mem.free as f32)},
            os:OS{name:os_name,version:os_version},
        };        
    }

    pub fn to_string(&self) -> String{
        let tmp = format!("Processor {}\nProcessor cores : {}\nMemory : {:.2} GB / {:.2} GB\nOS : {} {}",
            self.cpu.brand,self.cpu.cores,self.mem.free/GB,self.mem.total/GB,self.os.name,self.os.version);
        return String::from(tmp);
    }
}