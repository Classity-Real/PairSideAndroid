use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

#[cfg(target_os = "android")]
use android_logger::Config;

// Initialize Android logcat integration when the native library loads
#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _reserved: *mut std::os::raw::c_void) -> jint {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("SideInstallerRust"),
        );
    }
    log::info!("SideInstaller FFI library loaded into Android process.");
    jni::sys::JNI_VERSION_1_6
}

/// JNI bridge function called from Kotlin (`PairingHostManager.kt`)
/// Native method signature:
/// `private external fun nativeRunHost(bindIp: String, hostName: String, outputPath: String): Int`
#[no_mangle]
pub extern "system" fn Java_com_sideinstaller_host_PairingHostManager_nativeRunHost(
    mut env: JNIEnv,
    _class: JClass,
    bind_ip: JString,
    host_name: JString,
    output_path: JString,
) -> jint {
    // 1. Safely extract Java String parameters to Rust Strings
    let bind_str: String = match env.get_string(&bind_ip) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let name_str: String = match env.get_string(&host_name) {
        Ok(s) => s.into(),
        Err(_) => return -2,
    };

    let out_str: String = match env.get_string(&output_path) {
        Ok(s) => s.into(),
        Err(_) => return -3,
    };

    log::info!(
        "Invoking host server on bind_ip={}, host_name={}, output_path={}",
        bind_str,
        name_str,
        out_str
    );

    // 2. Convert to C-compatible CStrings
    let c_bind = CString::new(bind_str).unwrap_or_default();
    let c_name = CString::new(name_str).unwrap_or_default();
    let c_out = CString::new(out_str).unwrap_or_default();

    // 3. Execute the native pairing host routine
    let result_code = unsafe {
        si_pairing_run_host(
            c_bind.as_ptr(),
            c_name.as_ptr(),
            c_out.as_ptr(),
        )
    };

    log::info!("si_pairing_run_host finished with result code: {}", result_code);

    result_code as jint
}

// Internal / C-FFI declaration for the low-level pairing runner
extern "C" {
    fn si_pairing_run_host(
        bind_ip: *const c_char,
        host_name: *const c_char,
        output_path: *const c_char,
    ) -> c_int;
}
