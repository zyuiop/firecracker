use core::slice;
use std::{cmp, convert::TryInto, fmt::Display, fs::{File, OpenOptions}, io::{Read, Seek, SeekFrom}, mem, mem::size_of, os::unix::prelude::AsRawFd, path::PathBuf, ptr, sync::Arc};
use std::fmt::{Debug, Formatter};
use std::os::fd::RawFd;
use align_address::Align;
use kvm_bindings::{kvm_cpuid_entry2, kvm_memory_attributes, kvm_sev_cmd, kvm_sev_launch_measure, kvm_sev_launch_start, kvm_sev_launch_update_data, kvm_sev_snp_launch_finish, kvm_sev_snp_launch_start, kvm_sev_snp_launch_update, sev_cmd_id_KVM_SEV_ES_INIT, sev_cmd_id_KVM_SEV_INIT, sev_cmd_id_KVM_SEV_LAUNCH_FINISH, sev_cmd_id_KVM_SEV_LAUNCH_MEASURE, sev_cmd_id_KVM_SEV_LAUNCH_START, sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA, sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_VMSA, sev_cmd_id_KVM_SEV_SNP_LAUNCH_FINISH, sev_cmd_id_KVM_SEV_SNP_LAUNCH_START, sev_cmd_id_KVM_SEV_SNP_LAUNCH_UPDATE, KVM_SEV_SNP_PAGE_TYPE_CPUID, KVM_SEV_SNP_PAGE_TYPE_NORMAL, KVM_SEV_SNP_PAGE_TYPE_SECRETS, kvm_sev_init, sev_cmd_id_KVM_SEV_INIT2, KVM_CAP_EXIT_HYPERCALL, KVM_MEMORY_ATTRIBUTE_PRIVATE};
use kvm_ioctls::{HypercallExit, VmFd};
use linux_loader::bootparam::boot_e820_entry;
use sev::error::FirmwareError;
use sev::firmware::guest::GuestPolicy;
use sev::firmware::host::Firmware;
use sev::launch::PageType;
use sev::launch::snp::{Finish, Launcher, New, Start, Started, Update};
use thiserror::Error;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryBackend};
use crate::arch::KvmVm;
use crate::{info, warn, VmmError};
use crate::devices::pseudo::fw_cfg::KernelType;
use crate::initrd::InitrdConfig;
use crate::vmm_config::sev_config::SevConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// Length of intial boot time measurement
const MEASUREMENT_LEN: u32 = 48;
/// Where the SEV firmware will be loaded in guest memory (1MiB)
pub const FIRMWARE_ADDR: GuestAddress = GuestAddress(0x100000);
/// Where the fw_cfg device will load the kernel elf in chunks
pub const KERNEL_BOUNCE_BUFFER: GuestAddress = GuestAddress(0x1000000 - 0x200000);
/// Maximum length of the bzImage we can load (16MiB)
pub const KERNEL_BOUNCE_BUFFER_LEN: u64 = 0x200000;
/// Where the bzImage will be loaded
pub const BZIMAGE_ADDR: GuestAddress = GuestAddress(0x2000000);
/// Max bzimage length
pub const BZIMAGE_MAX_LEN: u64 = 0x1000000;
/// Where the GHCB page will be allocated by the firmware (48MiB)
pub const GHCB_ADDR_ELF: GuestAddress = GuestAddress(0x1000000 - 0x400000);
/// Where the GHCB page will be allocated by the firmware (48MiB)
pub const GHCB_ADDR_BZIMAGE: GuestAddress = GuestAddress(0x3000000);
/// Where the secrets page will be (50MiB)
pub const SECRETS_PAGE_ADDR: GuestAddress = GuestAddress(0x2000);
/// Length of the secrets page
pub const SECRETS_PAGE_LEN: u32 = 0x1000;
/// Where the secrets page will be (50MiB)
pub const CPUID_PAGE_ADDR: GuestAddress = GuestAddress(0x1000);
/// Length of the secrets page
pub const CPUID_PAGE_LEN: u32 = 0x1000;
//From SEV/KVM API SPEC
/// Debugging of the guest is disallowed when set
const _POLICY_NOBDG: u32 = 1;
/// Sharing keys with other guests is disallowed when set
const _POLICY_NOKS: u32 = 1 << 1;
/// SEV-ES is required when set
const POLICY_ES: u32 = 1 << 2;
/// Sending the guest to another platform is disallowed when set
const _POLICY_NOSEND: u32 = 1 << 3;
/// The guest must not be transmitted to another platform that is not in the domain when set
const _POLICY_DOMAIN: u32 = 1 << 4;
/// The guest must not be transmitted to another platform that is not SEV capable when set
const _POLICY_SEV: u32 = 1 << 5;
const PAGE_SIZE_2MB: u64 = 0x200000;
/// GHCB shared buffer size
const GHCB_SHARED_BUF_SIZE: usize = 0x7f0;
/// Maximum psc entries in ghcb shared buffer
const VMGEXIT_PSC_MAX_ENTRY: usize = 253;
//This excludes SUCCESS=0 and ACTIVE=18
#[derive(Debug, Error)]
/// SEV platform errors
pub enum SevError {
    FailedToOpenFirmware,
    /// The platform state is invalid for this command
    InvalidPlatformState,
    /// The guest state is invalid for this command
    InvalidGuestState,
    /// The platform configuration is invalid
    InvalidConfig,
    /// A memory buffer is too small
    InvalidLength,
    /// The platform is already owned
    AlreadyOwned,
    /// The certificate is invalid
    InvalidCertificate,
    /// Request is not allowed by guest policy
    PolicyFailure,
    /// The guest is inactive
    Inactive,
    /// The address provided is inactive
    InvalidAddress,
    /// The provided signature is invalid
    BadSignature,
    /// The provided measurement is invalid
    BadMeasurement,
    /// The ASID is already owned
    AsidOwned,
    /// The ASID is invalid
    InvalidAsid,
    /// WBINVD instruction required
    WBINVDRequired,
    ///DF_FLUSH invocation required
    DfFlushRequired,
    /// The guest handle is invalid
    InvalidGuest,
    /// The command issued is invalid
    InvalidCommand,
    /// A hardware condition has occurred affecting the platform. It is safe to re-allocate parameter buffers
    HwerrorPlatform,
    /// A hardware condition has occurred affecting the platform. Re-allocating parameter buffers is not safe
    HwerrorUnsafe,
    /// Feature is unsupported
    Unsupported,
    /// A parameter is invalid
    InvalidParam,
    /// The SEV FW has run out of a resource necessary to complete the command
    ResourceLimit,
    /// The part-specific SEV data failed integrity checks
    SecureDataInvalid,
    /// A mailbox mode command was sent while the SEV FW was in Ring Buffer mode.
    RbModeExited,
    /// The RMP page size is incorrect
    InvalidPageSize,
    /// The RMP page state is incorrect
    InvalidPageState,
    /// The metadata entry is invalid
    InvalidMDataEntry,
    /// The page ownership is incorrect
    InvalidPageOwner,
    /// The AEAD algorithm would have overflowed
    AeadOverflow,
    /// The RMP must be reinitialized
    RmpInitRequired,
    /// SVN of provided image is lower than the committed SVN
    BadSvn,
    /// Firmware version anti-rollback
    BadVersion,
    /// An invocation of SNP_SHUTDOWN is required to complete this action
    ShutdownRequired,
    /// Update of the firmware internal state or a guest context page has failed
    UpdateFailed,
    /// Installation of the committed firmware image required
    RestoreRequired,
    /// The RMP initialization failed
    RmpInitFailed,
    /// The key requested is invalid, not present, or not allowed
    InvalidKey,
    /// The error code returned by the SEV device is not valid
    InvalidErrorCode,
    /// Other error code
    Errno(i32),
    FirmwareError(FirmwareError),
}
#[derive(Debug)]
/// Temp
pub enum Error {
    /// Error loading SEV firmware
    FirmwareLoad,
}

impl Display for SevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<FirmwareError> for SevError {
    fn from(value: FirmwareError) -> Self {
        Self::FirmwareError(value)
    }
}

impl From<u32> for SevError {
    fn from(code: u32) -> Self {
        match code {
            0x01 => Self::InvalidPlatformState,
            0x02 => Self::InvalidGuestState,
            0x03 => Self::InvalidConfig,
            0x04 => Self::InvalidLength,
            0x05 => Self::AlreadyOwned,
            0x06 => Self::InvalidCertificate,
            0x07 => Self::PolicyFailure,
            0x08 => Self::Inactive,
            0x09 => Self::InvalidAddress,
            0x0a => Self::BadSignature,
            0x0b => Self::BadMeasurement,
            0x0c => Self::AsidOwned,
            0x0d => Self::InvalidAsid,
            0x0e => Self::WBINVDRequired,
            0x0f => Self::DfFlushRequired,
            0x10 => Self::InvalidGuest,
            0x11 => Self::InvalidCommand,
            0x13 => Self::HwerrorPlatform,
            0x14 => Self::HwerrorUnsafe,
            0x15 => Self::Unsupported,
            0x16 => Self::InvalidParam,
            0x17 => Self::ResourceLimit,
            0x18 => Self::SecureDataInvalid,
            0x1F => Self::RbModeExited,
            0x19 => Self::InvalidPageSize,
            0x1a => Self::InvalidPageState,
            0x1b => Self::InvalidMDataEntry,
            0x1c => Self::InvalidPageOwner,
            0x1d => Self::AeadOverflow,
            0x20 => Self::RmpInitRequired,
            0x21 => Self::BadSvn,
            0x22 => Self::BadVersion,
            0x23 => Self::ShutdownRequired,
            0x24 => Self::UpdateFailed,
            0x25 => Self::RestoreRequired,
            0x26 => Self::RmpInitFailed,
            0x27 => Self::InvalidKey,
            _ => Self::InvalidErrorCode,
        }
    }
}

/// SEV result return type
pub type SevResult<T> = std::result::Result<T, SevError>;
/// SEV Guest states
#[derive(Debug, PartialEq)]
pub enum State {
    /// The guest is uninitialized
    UnInit,
    /// The SEV platform has been initialized
    Init,
    /// The guest is currently beign launched and plaintext data and VMCB save areas are being imported
    LaunchUpdate,
    /// The guest is currently being launched and ciphertext data are being imported
    LaunchSecret,
    /// The guest is fully launched or migrated in, and not being migrated out to another machine
    Running,
    /// The guest is currently being migrated out to another machine
    SendUpdate,
    /// The guest is currently being migrated from another machine
    RecieveUpdate,
    /// The guest has been sent to another machine
    Sent,
}

#[derive(Debug)]
#[non_exhaustive]
struct MemoryRegion {
    start: GuestAddress,
    len: u64,
}

impl MemoryRegion {
    pub fn new(start: GuestAddress, len: u64) -> Self {
        let start_addr = start.0.align_down(0x1000);
        let added = start.0 - start_addr;
        let len = (len + added).align_up(0x1000);

        Self { start: GuestAddress(start_addr), len }
    }
}

#[derive(Default)]
struct WrappedLauncher(Option<Launcher<Started, RawFd, Firmware>>);

impl Debug for WrappedLauncher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0.is_some() {
            f.write_str("WrappedLauncher[Present]")
        } else {
            f.write_str("WrappedLauncher[Absent]")
        }
    }
}

/// Struct to hold SEV info
#[derive(Debug, Clone)]
pub struct Sev {
    pub original_config: SevConfig,
    pub kvm_vm: Arc<KvmVm>
}

#[repr(C, packed)]
struct PscHdr {
    cur_entry: u16,
    end_entry: u16,
    reserved: u32,
}

#[derive(Default, Copy, Clone)]
struct PscEntry(u64);

#[repr(C, packed)]
struct SnpPscDesc {
    hdr: PscHdr,
    entries: [PscEntry; VMGEXIT_PSC_MAX_ENTRY],
}

impl PscEntry {
    fn _get_cur_page(&self) -> u64 {
        self.0 & 0xfff
    }

    fn get_gfn(&self) -> u64 {
        (self.0 & (0xffffffffff << 12)) >> 12
    }

    fn get_operation(&self) -> u64 {
        (self.0 & (0xf << 52)) >> 52
    }

    fn get_page_size(&self) -> u64 {
        (self.0 & (1 << 56)) >> 56
    }
}

#[repr(C, packed)]
struct GhcbSaveArea {
    padding: [u8; 0x390],
    sw_exit_code: u64,
    sw_exit_info1: u64,
    sw_exit_indo2: u64,
}

#[repr(C, packed)]
struct Ghcb {
    save: GhcbSaveArea,
    reserved_save: [u8; 0x800 - std::mem::size_of::<GhcbSaveArea>()],
    shared_buffer: [u8; GHCB_SHARED_BUF_SIZE],
    reserved_1: [u8; 10],
    protocol_version: u16,
    ghcb_usage: u16,
}

pub struct SevLaunch<'a> {
    vm: &'a VmFd,
    config: SevConfig,
    timestamp: TimestampUs
}

impl<'a> SevLaunch<'a> {
    pub fn new(vm: &'a VmFd, config: SevConfig, timestamp: TimestampUs) -> Self {
        Self { vm, config, timestamp }
    }

    /// Initialize SEV-SNP platform
    pub fn snp_init(mut self) -> SevResult<SevStarted> {
        // Forward the guest's page state change requests (SNP GHCB protocol, shared<->private conversions) to userspace.
        let mut cap = kvm_bindings::kvm_enable_cap {
            cap: KVM_CAP_EXIT_HYPERCALL,
            ..Default::default()
        };
        cap.args[0] = 1 << 12;

        self.vm.enable_cap(&cap)
            .expect("Unable to enable the KVM_HC_MAP_GPA_RANGE hypercall exit");

        info!("Sending SNP_INIT");

        let mut firmware = Firmware::open().map_err(|_| SevError::FailedToOpenFirmware)?;
        firmware.platform_reset().expect("failed to reset");
        let launcher = Launcher::new(self.vm.as_raw_fd(), firmware)?;

        info!("Done Sending SNP_INIT");

        self.snp_launch_start(launcher)
    }

    fn snp_launch_start(mut self, launcher: Launcher<New, RawFd, Firmware>) -> SevResult<SevStarted> {
        info!("Sending SNP_LAUNCH_START");

        let mut policy = GuestPolicy::default();
        policy.set_debug_allowed(true);
        policy.set_smt_allowed(true);

        // reserved bit (17) and SMT (16) and debug (19)
        // let temp_policy = (1 << 16) | (1 << 17) | (1 << 19);
        let launcher = launcher.start(Start::new(policy, [0u8; 16]))?;

        info!("SNP_LAUNCH_START done");
        Ok(SevStarted {
            timestamp: self.timestamp,
            config: self.config,
            launcher,

            measured_regions: Vec::new(),
            ram_regions: Vec::new(),
            shared_regions: Vec::new()
        })
    }
}

pub struct SevStarted {
    config: SevConfig,
    timestamp: TimestampUs,
    launcher: Launcher<Started, RawFd, Firmware>,

    /// Regions to pre-encrypt
    measured_regions: Vec<MemoryRegion>,
    /// Regions that should be marked shared in the RMP
    shared_regions: Vec<MemoryRegion>,
    /// Regions that should be marked private in the RMP
    ram_regions: Vec<MemoryRegion>,
}

impl SevStarted {
    /// Add pre-encrypted region
    pub fn add_measured_region(&mut self, start: GuestAddress, len: u64) {
        self.measured_regions.push(MemoryRegion::new(start, len));
    }

    /// Add region that should be marked shared in the RMP
    pub fn add_shared_region(&mut self, start: GuestAddress, len: u64) {
        self.shared_regions.push(MemoryRegion::new(start, len));
    }

    /// Insert region of guest pages into guest physical memory
    fn snp_launch_update(
        &mut self,
        guest_addr: GuestAddress,
        len: u32,
        guest_mem: &GuestMemoryMmap,
        page_type: PageType,
    ) -> SevResult<()> {
        assert_eq!(len % 0x1000, 0, "len must be 4KiB aligned");
        assert_eq!(guest_addr.0 % 0x1000, 0, "guest addr must be 4KiB aligned");


        //extract guest frame number
        let gpa = guest_addr.0.align_down(0x1000);
        let gfn = gpa >> 12;
        let addr = guest_mem.get_host_address(guest_addr).unwrap() as u64;
        info!(
                "Registering encrypted memory region: start = 0x{:x}, size = 0x{:x}",
                gpa, len
            );

        let range = unsafe {
            let addr = ptr::with_exposed_provenance(addr as usize);
            slice::from_raw_parts(addr, len as usize)
        };

        self.launcher.update_data(Update::new(
            gfn, range, page_type
        ), gfn << 12, len as u64)?;

        Ok(())
    }

    /// Insert secrets page
    pub fn snp_insert_secrets_page(&mut self, guest_mem: &GuestMemoryMmap) -> SevResult<()> {
        info!("SNP inserting secrets page");
        self.snp_launch_update(
            SECRETS_PAGE_ADDR,
            SECRETS_PAGE_LEN,
            guest_mem,
            PageType::Secrets
        )?;
        Ok(())
    }

    /// Insert CPUID page
    pub fn snp_insert_cpuid_page(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        cpuid: &[kvm_cpuid_entry2],
    ) -> SevResult<()> {
        const CPUID_FUNCTION_COUNT_MAX: u32 = 64;

        #[repr(C, packed)]
        #[derive(Default, Copy, Clone, Debug)]
        struct CpuidFunction {
            eax_in: u32,
            ecx_in: u32,
            xcr0_in: u64,
            xss_in: u64,
            eax: u32,
            ebx: u32,
            ecx: u32,
            edx: u32,
            reserved: u64,
        }

        #[repr(C, packed)]
        struct CpuidPage {
            count: u32,
            reserved: u32,
            reserved1: u64,
            functions: [CpuidFunction; CPUID_FUNCTION_COUNT_MAX as usize],
        }

        info!("Inserting CPUID page");

        let mut page_entries = [CpuidFunction::default(); CPUID_FUNCTION_COUNT_MAX as usize];

        //construct list of cpuid entries
        for (i, entry) in cpuid.iter().enumerate() {
            let xcr0_in = if entry.function == 0xd {
                // (entry.edx as u64) << 32 | entry.eax as u64
                1
            } else {
                0
            };

            let func = CpuidFunction {
                eax_in: entry.function,
                ecx_in: entry.index,
                xcr0_in: xcr0_in,
                xss_in: 0,
                eax: entry.eax,
                ebx: entry.ebx,
                ecx: entry.ecx,
                edx: entry.edx,
                reserved: 0,
            };

            // println!("before: {:?}", func);

            //TODO check if i goes beyond max cpuid count
            if i == CPUID_FUNCTION_COUNT_MAX as usize {
                break;
            }
            page_entries[i] = func;
        }

        let cpuid_count = cmp::min(CPUID_FUNCTION_COUNT_MAX as usize, cpuid.len());
        let cpuid_page = CpuidPage {
            count: cpuid_count as u32,
            reserved: 0,
            reserved1: 0,
            functions: page_entries,
        };

        let p: *const CpuidPage = &cpuid_page;
        let p: *const u8 = p as *const u8;
        let slice: &[u8] = unsafe { slice::from_raw_parts(p, size_of::<CpuidPage>()) };

        guest_mem.write_slice(slice, CPUID_PAGE_ADDR).unwrap();

        match self.snp_launch_update(
            CPUID_PAGE_ADDR,
            CPUID_PAGE_LEN,
            guest_mem,
            PageType::Cpuid
        ) {
            Ok(()) => {}
            Err(_) => {
                //slight hack to have the PSP filter CPUID entries and we re-encrypt them here
                self.snp_launch_update(
                    CPUID_PAGE_ADDR,
                    CPUID_PAGE_LEN,
                    guest_mem,
                    PageType::Cpuid
                )?;
            }
        };

        Ok(())
    }

    /// call LAUNCH_UPDATE on all regions
    pub fn measure_regions(&mut self, guest_mem: &GuestMemoryMmap) -> SevResult<()> {
        let mut entry = self.measured_regions.pop();
        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!("Pre-encryption start: {:>06} us, {:>06} CPU us", real, cpu);
        while entry.is_some() {
            let region = entry.as_ref().unwrap();

            if region.start == FIRMWARE_ADDR {
                let now_tm_us = TimestampUs::default();
                let real = now_tm_us.time_us - self.timestamp.time_us;
                let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
                info!(
                    "Pre-encrypting firmware: {:>06} us, {:>06} CPU us",
                    real, cpu
                );
            }

            self.snp_launch_update(
                region.start,
                region.len.try_into().unwrap(),
                guest_mem,
                PageType::Normal
            )?;

            if region.start == FIRMWARE_ADDR {
                let now_tm_us = TimestampUs::default();
                let real = now_tm_us.time_us - self.timestamp.time_us;
                let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
                info!(
                    "Done pre-encrypting firmware: {:>06} us, {:>06} CPU us",
                    real, cpu
                );
            }

            entry = self.measured_regions.pop();
        }
        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!("Pre-encryption done: {:>06} us, {:>06} CPU us", real, cpu);
        Ok(())
    }

    /// Add rem regions to be marked private in RMP
    pub fn add_ram_regions(&mut self, entries: &[boot_e820_entry], count: usize) {
        for i in 0..count {
            let entry = entries[i];
            self.ram_regions.push(MemoryRegion::new(
                GuestAddress(entry.addr),
                entry.size,
            ));
        }
    }

    /// register ram regions for snp
    pub fn register_ram_regions(&mut self, vm: &VmFd) {
        let mut entry = self.ram_regions.pop();
        while entry.is_some() {
            let e = entry.as_ref().unwrap();
            let addr = e.start.0;
            let size = e.len.align_up(0x1000);

            info!(
                "Registering private memory region: start = 0x{:x}, size = 0x{:x}",
                addr, size
            );
            let attrs = kvm_memory_attributes {
                address: addr,
                size,
                attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE.into(),
                flags: 0,
            };

            vm.set_memory_attributes(attrs).unwrap();


            entry = self.ram_regions.pop();
        }
    }

    /// register shared regions for snp
    pub fn register_shared_regions(&mut self, vm: &VmFd) {
        let mut entry = self.shared_regions.pop();
        while entry.is_some() {
            let e = entry.as_ref().unwrap();
            let addr = e.start.0;
            let size = e.len;

            let aligned_size = if size > (size & !(0x1000 - 1)) {
                (size & !(0x1000 - 1)) + 0x1000
            } else {
                size
            };

            info!(
                "Registering shared memory region: start = 0x{:x}, size = 0x{:x}",
                addr, size
            );
            let attrs = kvm_memory_attributes {
                address: addr,
                size: aligned_size,
                attributes: 0,
                flags: 0,
            };

            vm.set_memory_attributes(attrs).unwrap();

            entry = self.shared_regions.pop();
        }
    }

    pub fn init_firmware_and_kernel(&mut self, kvm: &KvmVm, initrd: &Option<InitrdConfig>) -> Result<(), SevError> {
        self.load_firmware(kvm.guest_memory())?;
        self.snp_insert_cpuid_page(kvm.guest_memory(), kvm.common.kvm.supported_cpuid.as_slice())?;
        self.snp_insert_secrets_page(kvm.guest_memory())?;
        self.prepare_shared_regions();
        self.share_initrd(&initrd)
    }

    /// Finish SNP launch sequence
    pub fn snp_launch_finish(mut self, vm: Arc<KvmVm>) -> SevResult<Sev> {
        info!("SNP_LAUNCH_FINISH");

        // everything should be pre-encrypted by now so we can register memory
        self.register_ram_regions(vm.fd());
        // register the shared regions after registering ram because they probably overlap
        self.register_shared_regions(vm.fd());

        self.launcher.finish(Finish::new(
            None,
            None,
            [0u8; 32]
        ))?;

        info!("SNP_LAUNCH_FINISH DONE");
        Ok(Sev {
            original_config: self.config,
            kvm_vm: vm
        })
    }

    pub fn prepare_shared_regions(
        &mut self,
    ) {
        // set the plain text bounce buffer for kernel elf data shared
        self.add_shared_region(KERNEL_BOUNCE_BUFFER, KERNEL_BOUNCE_BUFFER_LEN);
        self.add_shared_region(GHCB_ADDR_ELF, PAGE_SIZE_2MB);
    }

    pub fn share_initrd(
        &mut self,
        initrd: &Option<InitrdConfig>,
    ) -> SevResult<()> {
        if let Some(initrd) = initrd {
            let initrd_load_addr = initrd.address.0;
            let initrd_size = initrd.size as u64;
            let align_to_pagesize = |address| address & !(0x200000 - 1);
            let load_addr_aligned = align_to_pagesize(initrd_load_addr);
            //plain text inird will be just before its final resting place
            let plain_text_addr = align_to_pagesize(load_addr_aligned - initrd_size);

            let size = if initrd_size > align_to_pagesize(initrd_size) {
                align_to_pagesize(initrd_size) + 0x200000
            } else {
                initrd_size
            };

            self.add_shared_region(GuestAddress(plain_text_addr), size);
        }

        Ok(())
    }

    ///Load SEV firmware
    pub fn load_firmware(&mut self, guest_mem: &GuestMemoryMmap) -> SevResult<()> {
        let path = PathBuf::from(&self.config.firmware_path);
        let mut f_firmware = File::open(path.as_path()).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();
        let len = f_firmware.seek(SeekFrom::End(0)).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();

        //put firmware in guest memory
        guest_mem
            .read_volatile_from(FIRMWARE_ADDR, &mut f_firmware, len.try_into().unwrap())
            .unwrap();

        self.add_measured_region(FIRMWARE_ADDR, len.try_into().unwrap());

        Ok(())
    }
}

impl Sev {
    /// Handle a vmgexit when the guest isn't using the MSR protocol
    pub fn handle_vmgexit(
        ghcb_msr: u64,
        guest_mem: &GuestMemoryMmap,
        vm_fd: &Arc<VmFd>,
    ) -> SevResult<()> {
        // info!("vmgexit ghcb msr: 0x{:x}", ghcb_msr);
        let ghcb_gpa = GuestAddress(ghcb_msr);
        let len = std::mem::size_of::<Ghcb>();

        //read the ghcb page from the guest
        let mut buf = vec![0u8; len];
        guest_mem.read_slice(&mut buf, ghcb_gpa).unwrap();

        let ghcb: &Ghcb = unsafe { std::mem::transmute::<_, &Ghcb>(buf.as_ptr()) };

        let mut shared_buf = vec![0u8; GHCB_SHARED_BUF_SIZE];
        shared_buf.copy_from_slice(&ghcb.shared_buffer);

        let desc: &mut SnpPscDesc =
            unsafe { std::mem::transmute::<_, &mut SnpPscDesc>(shared_buf.as_ptr()) };

        let cur_entry = desc.hdr.cur_entry;

        let mut entries = desc.entries;

        for i in cur_entry..(desc.hdr.end_entry + 1) {
            let entry = entries[i as usize];
            let private = entry.get_operation() == 1;

            Self::set_page_state(
                vm_fd,
                entry.get_gfn(),
                if entry.get_page_size() == 0 {
                    0x1000
                } else {
                    0x200000
                },
                private,
            );

            entries[i as usize] = PscEntry(entry.0 | 1);

            desc.hdr.cur_entry += 1;
        }

        let shared_buf_addr = GuestAddress(ghcb_msr + 0x800);
        // println!("{:?}", shared_buf);

        guest_mem.write_slice(&shared_buf, shared_buf_addr).unwrap();

        Ok(())
    }

    pub fn exit_set_page_state(&self, gpa: GuestAddress, n_pages: u64, flags: u64) -> SevResult<()> {
        const KVM_MAP_GPA_RANGE_ENCRYPTED: u64 = 1 << 4;
        const KVM_MAP_GPA_RANGE_SZ_2M: u64 = 1 << 0;
        const KVM_MAP_GPA_RANGE_SZ_1G: u64 = 1 << 1;

        let is_private = flags & KVM_MAP_GPA_RANGE_ENCRYPTED != 0;
        let is_large_pages = flags & KVM_MAP_GPA_RANGE_SZ_2M != 0;
        let is_huge_pages = flags & KVM_MAP_GPA_RANGE_SZ_1G != 0;

        if is_large_pages && is_huge_pages {
            panic!("invalid exit: cannot map both large and huge pages!");
        }

        // if `large_pages` is set, the number of pages is already set to 512:
        // https://elixir.bootlin.com/linux/v7.2.5/source/arch/x86/kvm/svm/sev.c#L3887
        //
        // For MSR calls, the size is always small anyway
        // https://elixir.bootlin.com/linux/v7.2.5/source/arch/x86/kvm/svm/sev.c#L3795
        let page_size = 0x1000;

        let address = gpa.0.align_down(page_size);

        let attrs = kvm_memory_attributes {
            attributes: if is_private { KVM_MEMORY_ATTRIBUTE_PRIVATE.into() } else { 0 },
            address,
            size: n_pages * page_size,
            flags: 0,
        };

        self.kvm_vm.fd().set_memory_attributes(attrs).unwrap();

        Ok(())
    }

    /// Change page state
    pub fn set_page_state(vm_fd: &Arc<VmFd>, gfn: u64, pg_size: u64, private: bool) {
        unimplemented!()
    }
}
