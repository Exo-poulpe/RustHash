extern crate raw_cpuid;
extern crate sysinfo; // Memory info + os info // Cpu info

use raw_cpuid::CpuId;
use sysinfo::{System, SystemExt,Process,ProcessExt};
use std::convert::*;
use std::string::String;

static GB: f32 = 1000000.;

pub struct CPU {
    pub brand: String,
    pub cores: i32,
}
pub struct MEM {
    pub total: f32,
    pub free: f32,
}
pub struct SysInfo {
    pub cpu: CPU,
    pub mem: MEM,
}
impl SysInfo {
    pub fn new() -> SysInfo {
        // CPU
        let cpuid = CpuId::new();
        let Strcores = 1;//sys_info::cpu_num().unwrap();
        let tmp = cpuid.get_extended_function_info().unwrap();
        let Strbrand = tmp.processor_brand_string().unwrap();
        let mut sys = System::new();
        sys.refresh_all();
        // MEM
        //let mem = {total=12,free=21};//sys_info::mem_info().unwrap();

        return SysInfo {
            cpu: CPU {
                brand: String::from(Strbrand),
                cores: (sys.get_processor_list().len() as i32 - 1),
            },
            mem: MEM {
                total: (sys.get_total_memory() as f32),
                free: ((sys.get_total_memory() - sys.get_used_memory()) as f32),
            },
        };
    }

    pub fn to_string(&self) -> String {
        let tmp = format!(
            "Processor {}\nProcessor cores : {}\nMemory : {:.2} GB / {:.2} GB\n",
            self.cpu.brand,
            self.cpu.cores,
            self.mem.free / GB,
            self.mem.total / GB,
        );
        return String::from(tmp);
    }
}
