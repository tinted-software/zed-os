use std::collections::HashMap;

pub struct Hardware {
    pub timers: HashMap<u32, u32>,
    pub gpio: HashMap<u32, u32>,
    pub clock_gates: HashMap<u32, u32>,
    pub power_mgmt: HashMap<u32, u32>,
}

impl Hardware {
    pub fn new() -> Self {
        let mut hw = Self {
            timers: HashMap::new(),
            gpio: HashMap::new(),
            clock_gates: HashMap::new(),
            power_mgmt: HashMap::new(),
        };

        // Initialize default values for iPad 1,1 Apple A4
        hw.init_defaults();
        hw
    }

    fn init_defaults(&mut self) {
        // Clock gates - all enabled
        self.clock_gates.insert(0x3C500010, 0xFFFFFFFF);
        self.clock_gates.insert(0x3C500020, 0xFFFFFFFF);

        // Power management - all powered on
        self.power_mgmt.insert(0x3C500000, 0x1);

        // Timers - running
        self.timers.insert(0x3C700000, 0x1000); // Timer counter

        // GPIO - default states
        self.gpio.insert(0x3CF00000, 0x0);
    }

    pub fn read(&self, addr: u32) -> Option<u32> {
        match addr {
            // Clock and Power Management Unit (CPMU)
            0x3C500000..=0x3C5000FF => self.power_mgmt.get(&addr).copied(),
            0x3C500010..=0x3C50002F => self.clock_gates.get(&addr).copied(),

            // Timer
            0x3C700000..=0x3C7000FF => {
                if addr == 0x3C700000 {
                    // Return incrementing timer value
                    Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u32,
                    )
                } else {
                    self.timers.get(&addr).copied()
                }
            }

            // GPIO
            0x3CF00000..=0x3CF000FF => self.gpio.get(&addr).copied(),

            // System Controller
            0x3D000000..=0x3D0000FF => Some(0x1), // Always ready

            _ => None,
        }
    }

    pub fn write(&mut self, addr: u32, value: u32) -> bool {
        match addr {
            // Clock and Power Management
            0x3C500000..=0x3C5000FF => {
                self.power_mgmt.insert(addr, value);
                true
            }
            0x3C500010..=0x3C50002F => {
                self.clock_gates.insert(addr, value);
                true
            }

            // Timer
            0x3C700000..=0x3C7000FF => {
                self.timers.insert(addr, value);
                true
            }

            // GPIO
            0x3CF00000..=0x3CF000FF => {
                self.gpio.insert(addr, value);
                true
            }

            // System Controller
            0x3D000000..=0x3D0000FF => true, // Accept writes

            _ => false,
        }
    }
}
