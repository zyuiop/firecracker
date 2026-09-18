use core::slice;
use std::{arch::x86_64::__cpuid, cmp, convert::TryInto, fmt::Display, fs::{File, OpenOptions}, io::{Read, Seek, SeekFrom}, mem::size_of, os::unix::prelude::AsRawFd, path::PathBuf, sync::Arc};

use kvm_bindings::{
    kvm_cpuid_entry2, kvm_memory_attributes, kvm_sev_cmd, kvm_sev_launch_measure,
    kvm_sev_launch_start, kvm_sev_launch_update_data, kvm_sev_snp_launch_finish,
    kvm_sev_snp_launch_start, kvm_sev_snp_launch_update, kvm_snp_init, sev_cmd_id_KVM_SEV_ES_INIT,
    sev_cmd_id_KVM_SEV_INIT, sev_cmd_id_KVM_SEV_LAUNCH_FINISH, sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
    sev_cmd_id_KVM_SEV_LAUNCH_START, sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA,
    sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_VMSA, sev_cmd_id_KVM_SEV_SNP_INIT,
    sev_cmd_id_KVM_SEV_SNP_LAUNCH_FINISH, sev_cmd_id_KVM_SEV_SNP_LAUNCH_START,
    sev_cmd_id_KVM_SEV_SNP_LAUNCH_UPDATE, KVM_SEV_SNP_PAGE_TYPE_CPUID,
    KVM_SEV_SNP_PAGE_TYPE_NORMAL, KVM_SEV_SNP_PAGE_TYPE_SECRETS,
};
use kvm_ioctls::VmFd;
use linux_loader::bootparam::boot_e820_entry;
use logger::info;
use thiserror::Error;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::InitrdConfig;
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
#[derive(PartialEq)]
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

struct MemoryRegion {
    start: GuestAddress,
    len: u64,
}

/// Struct to hold SEV info
pub struct Sev {
    fd: File,
    vm_fd: Arc<VmFd>,
    handle: u32,
    policy: u32,
    state: State,
    measure: [u8; 48],
    timestamp: TimestampUs,
    /// SNP active
    pub snp: bool,
    /// position of the Cbit
    pub cbitpos: u32,
    /// Whether the guest policy requires SEV-ES
    pub es: bool,
    /// Regions to pre-encrypt
    measured_regions: Vec<MemoryRegion>,
    /// Regions that should be marked shared in the RMP
    shared_regions: Vec<MemoryRegion>,
    /// Regions that should be marked private in the RMP
    ram_regions: Vec<MemoryRegion>,
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

impl Sev {
    ///Initialize SEV
    pub fn new(vm_fd: Arc<VmFd>, snp: bool, timestamp: TimestampUs, policy: u32) -> Self {
        //Open /dev/sev

        info!("Initializing new SEV guest context: policy 0x{:x}", policy);

        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sev")
            .unwrap();

        let ebx;

        //check if guest owner wants encrypted state
        let es = (policy & POLICY_ES) != 0;

        //Get position of the C-bit
        unsafe {
            ebx = __cpuid(0x8000001F).ebx & 0x3f;
        }

        Sev {
            fd: fd,
            vm_fd: vm_fd,
            handle: 0,
            policy: policy,
            state: State::UnInit,
            measure: [0u8; 48],
            cbitpos: ebx,
            snp: snp,
            timestamp,
            es,
            measured_regions: Vec::new(),
            shared_regions: Vec::new(),
            ram_regions: Vec::new(),
        }
    }

    /// Add pre-encrypted region
    pub fn add_measured_region(&mut self, start: GuestAddress, len: u64) {
        self.measured_regions.push(MemoryRegion { start, len });
    }

    /// Add region that should be marked shared in the RMP
    pub fn add_shared_region(&mut self, start: GuestAddress, len: u64) {
        self.shared_regions.push(MemoryRegion { start, len });
    }

    fn sev_ioctl(&mut self, cmd: &mut kvm_sev_cmd) -> SevResult<()> {
        match self.vm_fd.encrypt_op_sev(cmd) {
            Err(err) => {
                if cmd.error > 0 {
                    return Err(SevError::from(cmd.error));
                } else {
                    return Err(SevError::Errno(err.errno()));
                }
            }
            _ => Ok(()),
        }
    }

    /// Initialize SEV-SNP platform
    pub fn snp_init(&mut self) -> SevResult<()> {
        info!("Sending SNP_INIT");

        if self.state != State::UnInit {
            return Err(SevError::InvalidPlatformState);
        }

        let cmd = sev_cmd_id_KVM_SEV_SNP_INIT;

        let snp_init = kvm_snp_init { flags: 0 };

        let mut init = kvm_sev_cmd {
            id: cmd,
            data: &snp_init as *const kvm_snp_init as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut init)?;

        self.state = State::Init;
        info!("Done Sending SNP_INIT");

        self.snp_launch_start()
    }

    /// Initialize SEV platform
    pub fn sev_init(
        &mut self,
        session: &mut Option<File>,
        dh_cert: &mut Option<File>,
    ) -> SevResult<()> {
        info!("Sending SEV_INIT");

        if self.state != State::UnInit {
            return Err(SevError::InvalidPlatformState);
        }

        let cmd = if self.es {
            info!("Initializing SEV-ES");
            sev_cmd_id_KVM_SEV_ES_INIT
        } else {
            info!("Initializing SEV");
            sev_cmd_id_KVM_SEV_INIT
        };

        let mut init = kvm_sev_cmd {
            id: cmd,
            data: 0,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut init).unwrap();

        self.state = State::Init;
        info!("Done Sending SEV_INIT");

        self.sev_launch_start(session, dh_cert)
    }

    fn snp_launch_start(&mut self) -> SevResult<()> {
        info!("Sending SNP_LAUNCH_START");

        if self.state != State::Init {
            return Err(SevError::InvalidPlatformState);
        }

        // reserved bit (17) and SMT (16) and debug (19)
        let temp_policy = (1 << 16) | (1 << 17) | (1 << 19);

        self.policy = temp_policy;

        let start = kvm_sev_snp_launch_start {
            policy: temp_policy as u64,
            ..Default::default()
        };

        let mut cmd = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_SNP_LAUNCH_START,
            data: &start as *const kvm_sev_snp_launch_start as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut cmd)?;

        self.state = State::LaunchUpdate;
        info!("SNP_LAUNCH_START done");
        Ok(())
    }

    /// Get SEV guest handle
    fn sev_launch_start(
        &mut self,
        session: &mut Option<File>,
        dh_cert: &mut Option<File>,
    ) -> SevResult<()> {
        info!("LAUNCH_START");

        if self.state != State::Init {
            return Err(SevError::InvalidPlatformState);
        }

        let dh_cert_data = match dh_cert {
            None => None,
            Some(file) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                Some(buf)
            }
        };

        let (dh_cert_paddr, dh_cert_len) = match dh_cert_data.as_ref() {
            None => (0, 0),
            Some(buf) => (buf.as_ptr() as u64, buf.len() as u32),
        };

        let session_data = match session {
            None => None,
            Some(file) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                Some(buf)
            }
        };

        let (session_paddr, session_len) = match session_data.as_ref() {
            None => (0, 0),
            Some(buf) => (buf.as_ptr() as u64, buf.len() as u32),
        };

        let start = kvm_sev_launch_start {
            handle: 0,
            policy: self.policy,
            session_uaddr: session_paddr,
            session_len: session_len,
            dh_uaddr: dh_cert_paddr,
            dh_len: dh_cert_len,
        };

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_START,
            data: &start as *const kvm_sev_launch_start as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.handle = start.handle;
        self.state = State::LaunchUpdate;
        info!("LAUNCH_START Done");
        Ok(())
    }

    /// Insert region of guest pages into guest physical memory
    fn snp_launch_update(
        &mut self,
        guest_addr: GuestAddress,
        len: u32,
        guest_mem: &GuestMemoryMmap,
        page_type: u8,
    ) -> SevResult<()> {
        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        // info!(
        //     "SNP_LAUNCH_UPDATE, guest address = 0x{:x}, len = 0x{:x}",
        //     guest_addr.0, len
        // );

        //extract guest frame number
        let gfn = guest_addr.0 >> 12;
        let addr = guest_mem.get_host_address(guest_addr).unwrap() as u64;

        let update = kvm_sev_snp_launch_update {
            start_gfn: gfn,
            uaddr: addr,
            len: len,
            imi_page: 0,
            page_type: page_type,
            vmpl3_perms: 0,
            vmpl2_perms: 0,
            vmpl1_perms: 0,
        };

        //mark this mem as shared before encrypting
        let mut tmp = len as u64 + (addr - (addr & !0xfff));
        if (tmp % 4096) != 0 {
            tmp = tmp + (0x1000 - (tmp % 0x1000));
        }

        let attrs = kvm_memory_attributes {
            address: gfn << 12,
            size: tmp,
            attributes: 0,
            flags: 0,
        };

        self.vm_fd.set_memory_attributes(&attrs).unwrap();

        if attrs.size != 0 {
            println!("ERROR 0x{:x}", attrs.size);
        }

        let mut cmd = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_SNP_LAUNCH_UPDATE,
            data: &update as *const kvm_sev_snp_launch_update as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut cmd)?;

        Ok(())
    }

    /// Insert secrets page
    pub fn snp_insert_secrets_page(&mut self, guest_mem: &GuestMemoryMmap) -> SevResult<()> {
        if !self.snp {
            return Ok(());
        }

        info!("SNP inserting secrets page");
        self.snp_launch_update(
            SECRETS_PAGE_ADDR,
            SECRETS_PAGE_LEN,
            guest_mem,
            KVM_SEV_SNP_PAGE_TYPE_SECRETS.try_into().unwrap(),
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

        if !self.snp {
            return Ok(());
        }

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
            KVM_SEV_SNP_PAGE_TYPE_CPUID as u8,
        ) {
            Ok(()) => {}
            Err(_) => {
                //slight hack to have the PSP filter CPUID entries and we re-encrypt them here
                self.snp_launch_update(
                    CPUID_PAGE_ADDR,
                    CPUID_PAGE_LEN,
                    guest_mem,
                    KVM_SEV_SNP_PAGE_TYPE_CPUID as u8,
                )
                .unwrap();
            }
        };

        let mut buf = [0u8; size_of::<CpuidPage>()];

        guest_mem.read_slice(&mut buf, CPUID_PAGE_ADDR).unwrap();

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

            if self.snp {
                self.snp_launch_update(
                    region.start,
                    region.len.try_into().unwrap(),
                    guest_mem,
                    KVM_SEV_SNP_PAGE_TYPE_NORMAL as u8,
                )?;
            } else {
                self.launch_update_data(region.start, region.len.try_into().unwrap(), guest_mem)?;
            }

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
            self.ram_regions.push(MemoryRegion {
                start: GuestAddress(entry.addr),
                len: entry.size,
            });
        }
    }

    /// register ram regions for snp
    pub fn register_ram_regions(&mut self) {
        let mut entry = self.ram_regions.pop();
        while entry.is_some() {
            let e = entry.as_ref().unwrap();
            let addr = e.start.0;
            let size = e.len;

            let aligned_size = if size > (size & !(0x1000 - 1)) {
                (size & !(0x1000 - 1)) + 0x1000
            } else {
                size
            };

            // info!(
            //     "Registering private memory region: start = 0x{:x}, size = 0x{:x}",
            //     addr, size
            // );
            if self.snp {
                let attrs = kvm_memory_attributes {
                    address: addr,
                    size: aligned_size,
                    attributes: (1 << 3),
                    flags: 0,
                };

                self.vm_fd.set_memory_attributes(&attrs).unwrap();
            }

            entry = self.ram_regions.pop();
        }
    }

    /// register shared regions for snp
    pub fn register_shared_regions(&mut self) {
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

            // info!(
            //     "Registering shared memory region: start = 0x{:x}, size = 0x{:x}",
            //     addr, size
            // );
            let attrs = kvm_memory_attributes {
                address: addr,
                size: aligned_size,
                attributes: 0,
                flags: 0,
            };

            self.vm_fd.set_memory_attributes(&attrs).unwrap();

            entry = self.shared_regions.pop();
        }
    }

    /// Encrypt VMSA
    pub fn launch_update_vmsa(&mut self) -> SevResult<()> {
        if !self.es {
            return Ok(());
        }

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_VMSA,
            data: 0,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        info!("Encrypting VM save area...");

        self.sev_ioctl(&mut msg).unwrap();
        Ok(())
    }

    /// Encrypt region
    pub fn launch_update_data(
        &mut self,
        guest_addr: GuestAddress,
        len: u32,
        guest_mem: &GuestMemoryMmap,
    ) -> SevResult<()> {
        let addr = guest_mem.get_host_address(guest_addr).unwrap() as u64;

        let mut aligned_addr = addr;
        let mut aligned_len = len;

        if aligned_addr % 16 != 0 {
            aligned_addr -= addr % 16;
            aligned_len += (addr % 16) as u32;
        }

        if aligned_len % 16 != 0 {
            aligned_len = aligned_len - (aligned_len % 16) + 16;
        }

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let region = kvm_sev_launch_update_data {
            uaddr: aligned_addr,
            len: aligned_len,
        };

        //fill zeros between aligned (down) address and original address
        if aligned_addr < addr {
            let n = addr - aligned_addr;
            let mut buf = vec![0; n as usize];
            guest_mem
                .read_slice(&mut buf.as_mut_slice(), GuestAddress(guest_addr.0 - n))
                .unwrap();
        }

        let region_end = aligned_addr + aligned_len as u64;
        let original_end = addr + len as u64;

        //fill zeros between original end and end of aligned region
        if region_end > original_end {
            let n = region_end - original_end;
            let mut buf = vec![0; n as usize];
            guest_mem
                .read_slice(
                    &mut buf.as_mut_slice(),
                    GuestAddress(guest_addr.0 + len as u64),
                )
                .unwrap();
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA,
            data: &region as *const kvm_sev_launch_update_data as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        Ok(())
    }

    /// Get boot measurement
    pub fn get_launch_measurement(&mut self) -> SevResult<()> {
        info!("Sending LAUNCH_MEASURE");

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let mut measure: kvm_sev_launch_measure = Default::default();

        measure.uaddr = self.measure.as_ptr() as _;
        measure.len = MEASUREMENT_LEN;

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
            data: &measure as *const kvm_sev_launch_measure as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::LaunchSecret;
        info!("Done Sending LAUNCH_MEASURE");

        Ok(())
    }

    /// Finish SNP launch sequence
    pub fn snp_launch_finish(&mut self) -> SevResult<()> {
        info!("SNP_LAUNCH_FINISH");

        // everything should be pre-encrypted by now so we can register memory
        self.register_ram_regions();
        // register the shared regions after registering ram because they probably overlap
        self.register_shared_regions();

        let finish = kvm_sev_snp_launch_finish {
            id_block_uaddr: 0,
            id_auth_uaddr: 0,
            id_block_en: 0,
            auth_key_en: 0,
            host_data: [0u8; 32],
            ..Default::default()
        };

        let mut cmd = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_SNP_LAUNCH_FINISH,
            data: &finish as *const kvm_sev_snp_launch_finish as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut cmd)?;
        info!("SNP_LAUNCH_FINISH DONE");
        Ok(())
    }

    /// Finish SEV launch sequence
    pub fn sev_launch_finish(&mut self) -> SevResult<()> {
        self.register_ram_regions();
        self.register_shared_regions();
        info!("Sending LAUNCH_FINISH");

        if self.state != State::LaunchSecret {
            return Err(SevError::InvalidPlatformState);
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_FINISH,
            sev_fd: self.fd.as_raw_fd() as _,
            data: self.handle as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::Running;
        info!("Done Sending LAUNCH_FINISH");

        Ok(())
    }

    ///copy bzimage to guest memory
    pub fn load_kernel_and_initrd(
        &mut self,
        kernel_file: &mut File,
        is_bzimage: bool,
        guest_mem: &GuestMemoryMmap,
        initrd: &Option<InitrdConfig>,
    ) -> SevResult<u64> {
        let mut len = 0;

        if is_bzimage {
            kernel_file.seek(SeekFrom::Start(0)).unwrap();
            len = kernel_file.seek(SeekFrom::End(0)).unwrap();
            kernel_file.seek(SeekFrom::Start(0)).unwrap();

            //Load bzimage at 16mib
            guest_mem
                .read_exact_from(BZIMAGE_ADDR, kernel_file, len.try_into().unwrap())
                .unwrap();
        }

        if self.snp {
            if is_bzimage {
                //set the plain text region for the bzimage shared
                info!("kernel is bzimage");
                self.add_shared_region(BZIMAGE_ADDR, BZIMAGE_MAX_LEN);
                self.add_shared_region(GHCB_ADDR_BZIMAGE, PAGE_SIZE_2MB);
            } else {
                info!("kernel is elf");
                //set the plain text bounce buffer for kernel elf data shared
                self.add_shared_region(KERNEL_BOUNCE_BUFFER, KERNEL_BOUNCE_BUFFER_LEN);
                self.add_shared_region(GHCB_ADDR_ELF, PAGE_SIZE_2MB);
            }
        }

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

            if self.snp {
                self.add_shared_region(GuestAddress(plain_text_addr), size);
            }
        }

        Ok(len)
    }

    ///Load SEV firmware
    pub fn load_firmware(&mut self, path: &String, guest_mem: &GuestMemoryMmap) -> SevResult<()> {
        let path = PathBuf::from(path);
        let mut f_firmware = File::open(path.as_path()).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();
        let len = f_firmware.seek(SeekFrom::End(0)).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();

        //put firmware in guest memory
        guest_mem
            .read_exact_from(FIRMWARE_ADDR, &mut f_firmware, len.try_into().unwrap())
            .unwrap();

        self.add_measured_region(FIRMWARE_ADDR, len.try_into().unwrap());

        Ok(())
    }

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

    /// Change page state
    pub fn set_page_state(vm_fd: &Arc<VmFd>, gfn: u64, pg_size: u64, private: bool) {
        let attrs = kvm_memory_attributes {
            attributes: if private { 1 << 3 } else { 0 },
            address: gfn << if pg_size == 0x1000 { 12 } else { 21 },
            size: pg_size,
            flags: 0,
        };

        vm_fd.set_memory_attributes(&attrs).unwrap();

        if attrs.size != 0 {
            println!("ERROR 0x{:x}", attrs.size);
        }
    }
}
