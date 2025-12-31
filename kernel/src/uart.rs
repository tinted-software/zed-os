use core::fmt;
use core::fmt::Write;

pub struct Uart;

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let uart_ptr = 0x0900_0000 as *mut u8;
        for byte in s.bytes() {
            unsafe {
                uart_ptr.add(0).write_volatile(byte);
            }
        }
        Ok(())
    }
}

pub fn print_str(s: &str) {
    let _ = Uart.write_str(s);
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = crate::uart::Uart.write_fmt(format_args!($($arg)*));
    });
}

#[macro_export]
macro_rules! kprintln {
    () => (crate::kprint!("\n"));
    ($($arg:tt)*) => (crate::kprint!("{}\n", format_args!($($arg)*)));
}
