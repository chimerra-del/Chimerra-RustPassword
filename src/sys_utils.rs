use anyhow::{Context, Result};
use std::io::Error;

#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<()> {
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(Error::last_os_error())
                .context("Critical: Core Dumps is active (prctl)");
        }

        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            let err = Error::last_os_error();
            eprintln!("[!] WARNING: Failed to lock memory in RAM (mlockall): {}", err);
        }
    }
    Ok(())
}

// теперь винда работает
#[cfg(target_os = "windows")]
pub fn harden_process() -> Result<()> {
    use windows_sys::Win32::System::Threading::{
        SetProcessWorkingSetSize, GetCurrentProcess, 
        SetProcessMitigationPolicy, ProcessSignaturePolicy,
        PROCESS_MITIGATION_SIGNATURE_POLICY
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{SetErrorMode, SEM_NOGPFAULTERRORBOX};

    unsafe {
        let process = GetCurrentProcess();
        SetErrorMode(SEM_NOGPFAULTERRORBOX);
        if SetProcessWorkingSetSize(process, 1024 * 1024, 1024 * 1024 * 10) == 0 {
            let err = Error::last_os_error();
            eprintln!("[!] WARNING: Failed to set working set size (Windows): {}", err);
        }

        let mut sig_policy: PROCESS_MITIGATION_SIGNATURE_POLICY = std::mem::zeroed();
        sig_policy._bitfield = 1; // MicrosoftSignedOnly = 1
        SetProcessMitigationPolicy(ProcessSignaturePolicy, &sig_policy as *const _ as *const _, std::mem::size_of::<PROCESS_MITIGATION_SIGNATURE_POLICY>());
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn harden_process() -> Result<()> {
    eprintln!("[!] WARNING: Hardening is not implemented for this OS");
    Ok(())
}
