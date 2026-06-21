use super::client_impl::GuardianError;
use crate::ioctl::GUARDIAN_USER_DEVICE_PATH;
use std::ffi::c_void;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

pub struct GuardianDevice {
    handle: HANDLE,
}

impl GuardianDevice {
    pub fn open() -> Result<Self, GuardianError> {
        let path: Vec<u16> = GUARDIAN_USER_DEVICE_PATH
            .encode_utf16()
            .chain([0])
            .collect();
        unsafe {
            let handle = CreateFileW(
                PCWSTR(path.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?;
            if handle == INVALID_HANDLE_VALUE {
                return Err(GuardianError::DeviceOpenFailed);
            }
            Ok(Self { handle })
        }
    }

    pub fn ioctl(
        &self,
        code: u32,
        input: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<u32, GuardianError> {
        let mut bytes_returned = 0u32;
        let in_ptr = input
            .map(|b| b.as_ptr() as *const c_void)
            .unwrap_or(ptr::null());
        let in_len = input.map(|b| b.len() as u32).unwrap_or(0);
        unsafe {
            DeviceIoControl(
                self.handle,
                code,
                Some(in_ptr),
                in_len,
                Some(output.as_mut_ptr() as *mut c_void),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )?;
        }
        Ok(bytes_returned)
    }
}

impl Drop for GuardianDevice {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
