// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements Firecracker specific devices (e.g. signal when boot is completed).
mod boot_timer;
pub mod fw_cfg;
pub mod debug_port;

pub use self::boot_timer::BootTimer;
