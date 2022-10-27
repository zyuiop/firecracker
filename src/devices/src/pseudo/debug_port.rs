// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use crate::bus::BusDevice;
use logger::info;
use utils::time::TimestampUs;

pub struct DebugPort {
    timestamp: TimestampUs,
}

impl DebugPort {
    pub fn new(timestamp: TimestampUs) -> Self {
        Self { timestamp }
    }
}

impl BusDevice for DebugPort {
    fn write(&mut self, _offset: u64, data: &[u8]) {
        let code = data[0];
        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "[Debug code {:#04x}] {:>06} us, {:>06} CPU us",
            code, real, cpu
        );
    }
}
