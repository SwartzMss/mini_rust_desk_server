
pub use windows::*;
pub mod windows;
pub mod win_device;


use mini_rust_desk_common::{message_proto::CursorData, ResultType};
use std::sync::{Arc, Mutex};
pub const SERVICE_INTERVAL: u64 = 300;

pub fn change_resolution(name: &str, width: usize, height: usize) -> ResultType<()> {
    let cur_resolution = current_resolution(name)?;
    if cur_resolution.width as usize == width && cur_resolution.height as usize == height {
        return Ok(());
    }
    mini_rust_desk_common::log::warn!("Change resolution of '{}' to ({},{})", name, width, height);
    change_resolution_directly(name, width, height)
}


pub fn get_wakelock(_display: bool) -> WakeLock {
    mini_rust_desk_common::log::info!("new wakelock, require display on: {_display}");
    // display：保持屏幕打开
    // idle: CPU处于开启状态
    // sleep：禁止系统休眠，即使是手动休眠
    return crate::platform::WakeLock::new(_display, true, false);
}
