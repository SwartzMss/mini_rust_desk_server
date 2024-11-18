use mini_rust_desk_common::{log, thiserror};
use std::{
    ffi::OsStr,
    io,
    ops::{Deref, DerefMut},
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
    result::Result,
};
use winapi::{
    shared::{
        guiddef::GUID,
        minwindef::{BOOL, DWORD, FALSE, MAX_PATH, PBOOL, TRUE},
        ntdef::{HANDLE, LPCWSTR, NULL},
        windef::HWND,
        winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS},
    },
    um::{
        cfgmgr32::MAX_DEVICE_ID_LEN,
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        ioapiset::DeviceIoControl,
        setupapi::*,
        winnt::{GENERIC_READ, GENERIC_WRITE},
    },
};

#[link(name = "Newdev")]
extern "system" {
    fn UpdateDriverForPlugAndPlayDevicesW(
        hwnd_parent: HWND,
        hardware_id: LPCWSTR,
        full_inf_path: LPCWSTR,
        install_flags: DWORD,
        b_reboot_required: PBOOL,
    ) -> BOOL;
}

#[derive(thiserror::Error, Debug)]
pub enum DeviceError {
    #[error("Failed to call {0}, {1:?}")]
    WinApiLastErr(String, io::Error),
    #[error("Failed to call {0}, returns {1}")]
    WinApiErrCode(String, DWORD),
    #[error("{0}")]
    Raw(String),
}

impl DeviceError {
    #[inline]
    fn new_api_last_err(api: &str) -> Self {
        Self::WinApiLastErr(api.to_string(), io::Error::last_os_error())
    }
}

struct DeviceInfo(HDEVINFO);

impl DeviceInfo {
    fn setup_di_create_device_info_list(class_guid: &mut GUID) -> Result<Self, DeviceError> {
        let dev_info = unsafe { SetupDiCreateDeviceInfoList(class_guid, null_mut()) };
        if dev_info == null_mut() {
            return Err(DeviceError::new_api_last_err("SetupDiCreateDeviceInfoList"));
        }

        Ok(Self(dev_info))
    }

    fn setup_di_get_class_devs_ex_w(
        class_guid: *const GUID,
        flags: DWORD,
    ) -> Result<Self, DeviceError> {
        let dev_info = unsafe {
            SetupDiGetClassDevsExW(
                class_guid,
                null_mut(),
                null_mut(),
                flags,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if dev_info == null_mut() {
            return Err(DeviceError::new_api_last_err("SetupDiGetClassDevsExW"));
        }
        Ok(Self(dev_info))
    }
}

impl Drop for DeviceInfo {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

impl Deref for DeviceInfo {
    type Target = HDEVINFO;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DeviceInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

unsafe fn is_same_hardware_id(
    dev_info: &DeviceInfo,
    devinfo_data: &mut SP_DEVINFO_DATA,
    hardware_id: &str,
) -> Result<bool, DeviceError> {
    let mut cur_hardware_id = [0u16; MAX_DEVICE_ID_LEN];
    if SetupDiGetDeviceRegistryPropertyW(
        **dev_info,
        devinfo_data,
        SPDRP_HARDWAREID,
        null_mut(),
        cur_hardware_id.as_mut_ptr() as _,
        cur_hardware_id.len() as _,
        null_mut(),
    ) == FALSE
    {
        return Err(DeviceError::new_api_last_err(
            "SetupDiGetDeviceRegistryPropertyW",
        ));
    }

    let cur_hardware_id = String::from_utf16_lossy(&cur_hardware_id)
        .trim_end_matches(char::from(0))
        .to_string();
    Ok(cur_hardware_id == hardware_id)
}

pub unsafe fn device_io_control(
    interface_guid: &GUID,
    control_code: u32,
    inbuf: &[u8],
    outbuf_max_len: usize,
) -> Result<Vec<u8>, DeviceError> {
    let h_device = open_device_handle(interface_guid)?;
    let mut bytes_returned = 0;
    let mut outbuf: Vec<u8> = vec![];
    let outbuf_ptr = if outbuf_max_len > 0 {
        outbuf.reserve(outbuf_max_len);
        outbuf.as_mut_ptr()
    } else {
        null_mut()
    };
    let result = DeviceIoControl(
        h_device,
        control_code,
        inbuf.as_ptr() as _,
        inbuf.len() as _,
        outbuf_ptr as _,
        outbuf_max_len as _,
        &mut bytes_returned,
        null_mut(),
    );
    CloseHandle(h_device);
    if result == FALSE {
        return Err(DeviceError::new_api_last_err("DeviceIoControl"));
    }
    if outbuf_max_len > 0 {
        outbuf.set_len(bytes_returned as _);
        Ok(outbuf)
    } else {
        Ok(Vec::new())
    }
}

unsafe fn get_device_path(interface_guid: &GUID) -> Result<Vec<u16>, DeviceError> {
    let dev_info = DeviceInfo::setup_di_get_class_devs_ex_w(
        interface_guid,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
    )?;
    let mut device_interface_data = SP_DEVICE_INTERFACE_DATA {
        cbSize: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as _,
        InterfaceClassGuid: *interface_guid,
        Flags: 0,
        Reserved: 0,
    };
    if SetupDiEnumDeviceInterfaces(
        *dev_info,
        null_mut(),
        interface_guid,
        0,
        &mut device_interface_data,
    ) == FALSE
    {
        return Err(DeviceError::new_api_last_err("SetupDiEnumDeviceInterfaces"));
    }

    let mut required_length = 0;
    if SetupDiGetDeviceInterfaceDetailW(
        *dev_info,
        &mut device_interface_data,
        null_mut(),
        0,
        &mut required_length,
        null_mut(),
    ) == FALSE
    {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as _) {
            return Err(DeviceError::WinApiLastErr(
                "SetupDiGetDeviceInterfaceDetailW".to_string(),
                err,
            ));
        }
    }

    let predicted_length = required_length;
    let mut vec_data: Vec<u8> = Vec::with_capacity(required_length as _);
    let device_interface_detail_data = vec_data.as_mut_ptr();
    let device_interface_detail_data =
        device_interface_detail_data as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
    (*device_interface_detail_data).cbSize =
        std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as _;
    if SetupDiGetDeviceInterfaceDetailW(
        *dev_info,
        &mut device_interface_data,
        device_interface_detail_data,
        predicted_length,
        &mut required_length,
        null_mut(),
    ) == FALSE
    {
        return Err(DeviceError::new_api_last_err(
            "SetupDiGetDeviceInterfaceDetailW",
        ));
    }

    let mut path = Vec::new();
    let device_path_ptr =
        std::ptr::addr_of!((*device_interface_detail_data).DevicePath) as *const u16;
    let steps = device_path_ptr as usize - vec_data.as_ptr() as usize;
    for i in 0..(predicted_length - steps as u32) / 2 {
        if *device_path_ptr.offset(i as _) == 0 {
            path.push(0);
            break;
        }
        path.push(*device_path_ptr.offset(i as _));
    }
    Ok(path)
}

unsafe fn open_device_handle(interface_guid: &GUID) -> Result<HANDLE, DeviceError> {
    let device_path = get_device_path(interface_guid)?;
    let h_device = CreateFileW(
        device_path.as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        null_mut(),
        OPEN_EXISTING,
        0,
        null_mut(),
    );
    if h_device == INVALID_HANDLE_VALUE || h_device == NULL {
        return Err(DeviceError::new_api_last_err("CreateFileW"));
    }
    Ok(h_device)
}
