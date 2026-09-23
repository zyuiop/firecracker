use std::sync::{Arc, Barrier, Mutex};
// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use utils::time::TimestampUs;
use crate::arch::KvmVm;
use crate::devices::pseudo::fw_cfg::FW_CFG_REG_ADDRESS;
use crate::info;
use crate::vstate::bus::BusDevice;

#[derive(Debug)]
pub struct DebugPort {
    timestamp: TimestampUs,
}

impl DebugPort {
    pub fn new(timestamp: TimestampUs) -> Self {
        Self { timestamp }
    }
}

impl BusDevice for DebugPort {
    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let code = data[0];
        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "[Debug code {:#04x}] {:>06} us, {:>06} CPU us",
            code, real, cpu
        );

        None
    }
}