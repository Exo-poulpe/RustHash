extern crate raw_cpuid;
//extern crate sys_info; // Memory info + os info // Cpu info

use raw_cpuid::CpuId;
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
        let Strcores = 1;//sys_info::cpu_num().unwrap();
        let tmp = cpuid.get_extended_function_info().unwrap();
        let Strbrand = tmp.processor_brand_string().unwrap();

        // MEM
        //let mem = {total=12,free=21};//sys_info::mem_info().unwrap();

        // OS
        let os_name = "moi".to_string();//sys_info::os_type().unwrap();
        let os_version = "21".to_string();// sys_info::os_release().unwrap();

        return SysInfo {
            cpu: CPU {
                brand: String::from(Strbrand),
                cores: (Strcores as i32),
            },
            mem: MEM {
                total: (12 as f32),
                free: (11 as f32),
            },
            os: OS {
                name: os_name,
                version: os_version,
            },
        };
    }

    pub fn to_string(&self) -> String {
        let tmp = format!(
            "Processor {}\nProcessor cores : {}\nMemory : {:.2} GB / {:.2} GB\nOS : {} {}",
            self.cpu.brand,
            self.cpu.cores,
            self.mem.free / GB,
            self.mem.total / GB,
            self.os.name,
            self.os.version
        );
        return String::from(tmp);
    }
}
