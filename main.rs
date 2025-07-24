use sysinfo::System;
use process_memory::{Pid, DataMember, Memory, TryIntoProcessHandle};
use mach2::{vm_types::{vm_address_t, vm_size_t}, traps::{task_for_pid, mach_task_self}, kern_return::KERN_SUCCESS, vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info}, message::mach_msg_type_number_t, port::{mach_port_t, }, vm::{mach_vm_region}, vm_prot::{VM_PROT_EXECUTE}};
use std::{time::Duration, thread};
use crossterm::event::{self, Event, KeyCode};

fn get_base_address(pid: i32) -> Option<vm_address_t> {
    unsafe {
        let mut task: mach_port_t = 0;
        // Mach kernel api call that tries to get the mach task port for the specified task
        if task_for_pid(mach_task_self(), pid, &mut task) != KERN_SUCCESS {
            return None;
        }

        let mut address: vm_address_t = 1;
        let mut size: vm_size_t = 0;
        let mut info: vm_region_basic_info = std::mem::zeroed();
        let mut info_count = std::mem::size_of_val(&info) as mach_msg_type_number_t;
        let mut object_name: mach_port_t = 0;
        
        // checks each of the specified virtual memory regions and returns info associated with it
        while mach_vm_region( task, &mut address as *mut _ as *mut u64, &mut size as *mut _ as *mut u64, VM_REGION_BASIC_INFO_64, &mut info as *mut _ as *mut i32, &mut info_count, &mut object_name) == KERN_SUCCESS {
            // Check info that is returned is executable then return the base address
            if info.protection & VM_PROT_EXECUTE != 0 {
                // Assaultcube binary starts where the base address starts
                return Some(address);
            }
            // If memory is not executable, then the current address is added with the returned size 
            address += size;
        }
    }

    None

}

fn patch_health(offsets: Vec<u64>, base_address: usize, pid: i32) {
    // Set handle for the process
    let handle = (pid as Pid).try_into_process_handle().unwrap();
    // Loop through offsets and use them on corresponding address in order to go up to pointer stack and locate the health value
    let mut current_address = base_address;
    let mut member: DataMember<u64> = DataMember::new(handle);
    for index in 0..offsets.len() {
        member = DataMember::new_offset(handle, vec![current_address + offsets[index] as usize]);
        unsafe {
            match member.read() {
                Ok(value) => current_address = value as usize,
                Err(e) => println!("Error {}", e),
            }
        }
    }

    let health_value = 9999; 
    member.write(&health_value).unwrap()

}

fn main() {
    let mut system = System::new_all();
    system.refresh_all();

    let mut pid: i32 = 0;
    for process in system.processes_by_exact_name("assaultcube".as_ref()) {
        pid = process.pid().as_u32() as i32;
    }

    println!("Target process PID: {}", pid);

    let health_offsets = vec![0x1D9EF0, 0x0, 0x418];
    let mut patching = false;

    println!("Press 'g' to toggle health patching on/off. Press 'q' to quit.");

    loop {
        // Check for key events
        if event::poll(Duration::from_millis(50)).unwrap() {
            if let Event::Key(key_event) = event::read().unwrap() {
                match key_event.code {
                    KeyCode::Char('g') => {
                        patching = !patching;
                        println!("Patching toggled {}.", if patching { "ON" } else { "OFF" });
                    }
                    KeyCode::Char('q') => {
                        println!("Exiting...");
                        break;
                    }
                    _ => {}
                }
            }
        }

        if patching {
            let mut base_address = 0;
            match get_base_address(pid) {
                Some(value) => base_address = value,
                None => {
                    println!("Base address not found!");
                    thread::sleep(Duration::from_millis(1000));
                    continue;
                }
            }

            patch_health(health_offsets.clone(), base_address, pid);
            thread::sleep(Duration::from_millis(16));
        } else {
            thread::sleep(Duration::from_millis(100));
        }
    }
}