use std::{
    convert::TryFrom,
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem,
};
use std::mem::size_of;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Barrier, Mutex};
use goblin::elf64;
use linux_loader::{bootparam::setup_header, elf as elf_magic};
use goblin::elf::Elf;
use goblin::elf::program_header::ProgramHeader;
use goblin::elf64::header::{Header as Elf64Header};
use goblin::elf64::sym::sym64;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::reloc::reloc64;
use scroll::ctx::TryIntoCtx;
use scroll::Endian;
use vm_memory::{ByteValued, Bytes, GuestAddress, ReadVolatile};

use crate::{warn, info, Kvm};
use crate::arch::KvmVm;
use crate::arch::x86_64::sev::{Sev, SevStarted};
use crate::vstate::bus::BusDevice;
use crate::vstate::memory::GuestMemoryMmap;

//Constants for partial loading the kernel
const BZIMAGE_HEADER_OFFSET: u64 = 0x1f1;
const BZIMAGE_HEADER_MAGIC: u32 = 0x53726448;

const BZIMAGE_CODE: u32 = 0x0;
const DIRECT_CODE: u32 = 0x1;
const DATA_REGION_SIZE: u64 = 0x200000;
const DATA_REGION_ADDR: u64 = 0x1000000 - 0x200000;
pub const FW_CFG_REG_ADDRESS: u64 = 0x81;

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum KernelType {
    BzImage,
    Direct,
}

#[derive(Debug, PartialEq)]
enum State {
    WriteKernelType,
    WriteElfHdr,
    WritePhdrs,
    WriteSegs,
    WriteBzImageLen,
}

#[derive(Debug)]
enum Command {
    ///Get the type of kernel to load, should be the first command issued
    KernelType,
    ///Get the length of the bzImage
    BzImageLen,
    ///Start reading the bzImage in chunks
    BzimageData,
    ///For a direct boot, send the ELF header
    ElfHdr,
    ///For a direct boot, get the next phdr
    PhdrData,
    ///Start reading loadable segment data
    SegData,
    ///For a direct boot, send the Relocation data
    ElfRela,
    ElfDynSym,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    InvalidElfMagicNumber,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    ReadKernelDataStruct(&'static str),
    SeekKernelStart,
    SeekKernelImage,
    SeekProgramHeader,
    InvalidCommand,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::BigEndianElfOnLittle => "Unsupported ELF File byte order",
                Error::InvalidElfMagicNumber => "Invalid ELF magic number",
                Error::InvalidProgramHeaderSize => "Invalid ELF program header size",
                Error::InvalidProgramHeaderOffset => "Invalid ELF program header offset",
                Error::ReadKernelDataStruct(ref e) => e,
                Error::SeekKernelStart => {
                    "Failed to seek to file offset as pointed by the ELF program header"
                }
                Error::SeekKernelImage => "Failed to seek to offset of kernel image",
                Error::SeekProgramHeader => "Failed to seek to ELF program header",
                Error::InvalidCommand => "Invalid command",
            }
        )
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::KernelType),
            1 => Ok(Self::BzImageLen),
            2 => Ok(Self::BzimageData),
            3 => Ok(Self::ElfHdr),
            4 => Ok(Self::PhdrData),
            5 => Ok(Self::SegData),
            6 => Ok(Self::ElfRela),
            7 => Ok(Self::ElfDynSym),
            _ => Err(Error::InvalidCommand),
        }
    }
}

impl Into<u32> for Command {
    fn into(self) -> u32 {
        match self {
            Self::KernelType => 0,
            Self::BzImageLen => 1,
            Self::BzimageData => 2,
            Self::ElfHdr => 3,
            Self::PhdrData => 4,
            Self::SegData => 5,
            Self::ElfRela => 6,
            Self::ElfDynSym => 7,
        }
    }
}

impl KernelType {
    fn value(&self) -> u8 {
        match *self {
            Self::BzImage => BZIMAGE_CODE as u8,
            Self::Direct => DIRECT_CODE as u8,
        }
    }
}

#[derive(Debug)]
pub struct FwCfg {
    vm: Arc<KvmVm>,
    kernel: Vec<u8>,
    kernel_type: KernelType,
    ehdr: Option<Elf64Header>,
    phdrs: Option<Vec<ProgramHeader>>,

    rela: Vec<reloc64::Rela>,
    dyn_syms: Vec<sym64::Sym>,

    cur_phdr: usize,
    seg_pos: u64,
    cmd: Option<Command>,
    state: State,
}

impl FwCfg {
    fn mem(&self) -> &GuestMemoryMmap {
        self.vm.guest_memory()
    }

    pub fn new(
        mut kernel: File,
        kernel_hashes_path: &String,
        initrd_hashes_path: &Option<String>,
        vm: Arc<KvmVm>,
        sev: Option<&mut SevStarted>,
    ) -> Self {
        info!("Creating fw_cfg device");

        let kernel_type = get_kernel_type(&mut kernel);
        let mut kernel_data = Vec::with_capacity(kernel.metadata().map(|meta| meta.size() as usize).unwrap_or(1024));

        kernel.seek(SeekFrom::Start(0)).expect("Unable to seek to start of kernel file");
        kernel.read_to_end(&mut kernel_data).expect("Failed to read kernel data");

        let mut fw_cfg = FwCfg {
            vm,
            kernel: kernel_data,
            kernel_type,
            ehdr: None,
            phdrs: None,
            rela: vec![],
            cmd: None,
            cur_phdr: 0,
            seg_pos: 0,
            state: State::WriteElfHdr,
            dyn_syms: vec![],
        };

        //Try to parallelize this somehow in the future
        if kernel_type == KernelType::Direct {
            fw_cfg.setup_direct_boot().unwrap();
            assert!(fw_cfg.phdrs.is_some());
            assert!(!fw_cfg.phdrs.as_ref().unwrap().is_empty());
        }

        fw_cfg.add_kernel_hashes(kernel_hashes_path, initrd_hashes_path, sev);

        fw_cfg
    }

    pub fn kernel_type(&self) -> KernelType {
        self.kernel_type
    }

    fn add_kernel_hashes(
        &self,
        kernel_hashes_path: &String,
        initrd_hashes_path: &Option<String>,
        sev: Option<&mut SevStarted>,
    ) {
        let mut hashes_base_address = GuestAddress(crate::arch::x86_64::sev::FIRMWARE_ADDR.0 - 32);
        let mut hashes_len = 32;

        let mut kernel_hashes = File::open(kernel_hashes_path).unwrap();
        self.mem()
            .read_volatile_from(hashes_base_address, &mut kernel_hashes, 32)
            .unwrap();

        //add initrd hashes if booting with initrd
        if let Some(initrd_hashes_path) = initrd_hashes_path.as_ref() {
            hashes_base_address = GuestAddress(hashes_base_address.0 - 32);
            hashes_len = 64;

            let mut initrd_hashes = File::open(initrd_hashes_path).unwrap();
            self.mem()
                .read_volatile_from(hashes_base_address, &mut initrd_hashes, 32)
                .unwrap();
        }

        if let Some(sev) = sev {
            sev.add_measured_region(hashes_base_address, hashes_len);
        }
    }

    ///Parse uncompressed kernel ELF and save loadable phdrs/entry point
    fn setup_direct_boot(&mut self) -> Result<(), Error> {
        let elf = Elf::parse(&self.kernel).expect("failed to parse ELF");

        let ehdr = elf.header;
        // Sanity checks
        if ehdr.e_ident[elf_magic::EI_MAG0 as usize] != elf_magic::ELFMAG0 as u8
            || ehdr.e_ident[elf_magic::EI_MAG1 as usize] != elf_magic::ELFMAG1
            || ehdr.e_ident[elf_magic::EI_MAG2 as usize] != elf_magic::ELFMAG2
            || ehdr.e_ident[elf_magic::EI_MAG3 as usize] != elf_magic::ELFMAG3
        {
            return Err(Error::InvalidElfMagicNumber);
        }
        if ehdr.e_ident[elf_magic::EI_DATA as usize] != elf_magic::ELFDATA2LSB as u8 {
            return Err(Error::BigEndianElfOnLittle);
        }
        if ehdr.e_phentsize as usize != mem::size_of::<ProgramHeader>() {
            return Err(Error::InvalidProgramHeaderSize);
        }
        if (ehdr.e_phoff as usize) < mem::size_of::<ProgramHeader>() {
            // If the program header is backwards, bail.
            return Err(Error::InvalidProgramHeaderOffset);
        }

        let mut phdrs = elf.program_headers;

        self.rela = elf.dynrelas
            .iter()
            .map(|rela| reloc64::Rela::from(rela))
            .collect();

        self.dyn_syms = elf.dynsyms
            .iter()
            .map(|sym| sym64::Sym::from(sym))
            .collect();

        self.ehdr = Some(ehdr.into());
        self.phdrs = Some(phdrs);

        Ok(())
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let vm = Arc::clone(&self.vm);
        let mem = vm.guest_memory();
        info!("FW_CFG READ");

        if offset != 0 || data.len() < 1 {
            info!("fw_cfg invalid read address");
        } else {
            match self.cmd {
                Some(Command::KernelType) => {
                    info!("KERNEL TYPE");
                    if self.state == State::WriteKernelType {
                        let type_buf = u8::to_le_bytes(self.kernel_type.value());
                        data.copy_from_slice(&type_buf);
                        if self.kernel_type == KernelType::Direct {
                            self.state = State::WriteElfHdr;
                        } else {
                            self.state = State::WriteBzImageLen;
                        }
                    } else {
                        warn!("Invalid state");
                    }
                }
                Some(Command::ElfHdr) => {
                    if self.state == State::WriteElfHdr {
                        // Elf header is small so it can all be written in one chunk
                        let mut output = [0u8; elf64::header::SIZEOF_EHDR];
                        self.ehdr.unwrap().try_into_ctx(&mut output, Endian::Little)
                            .expect("failed to read Elf HDR");

                        mem.write_slice(
                                &output,
                                GuestAddress(DATA_REGION_ADDR),
                            )
                            .unwrap();
                        self.state = State::WritePhdrs;
                    } else {
                        warn!("Invalid state")
                    }
                }
                Some(Command::PhdrData) => {
                    if self.state == State::WritePhdrs {
                        if let Some(phdrs) = &mut self.phdrs {
                            let phdr = phdrs.get(self.cur_phdr).unwrap();
                            let phdr = elf64::program_header::ProgramHeader::from(phdr.clone());
                            let mut output = [0u8; size_of::<elf64::program_header::ProgramHeader>()];
                            phdr.try_into_ctx(&mut output, Endian::Little).expect("failed to serialize program header!");

                            mem.write_slice(&output, GuestAddress(DATA_REGION_ADDR))
                                .unwrap();

                            self.cur_phdr += 1;

                            if self.cur_phdr == phdrs.len() {
                                self.cur_phdr = 0;
                                self.state = State::WriteSegs;
                            }
                        } else {
                            warn!("phdrs is empty");
                        }
                    } else {
                        warn!("Invalid state");
                    }
                }
                Some(Command::SegData) => {
                    if self.state == State::WriteSegs {
                        if let Some(phdrs) = &mut self.phdrs {
                            //Get phdr for segment to write
                            let mut phdr = phdrs.get(self.cur_phdr).unwrap();
                            if phdr.p_filesz == 0 || phdr.p_type != PT_LOAD {
                                self.cur_phdr += 1;
                                if self.cur_phdr >= phdrs.len() {
                                    return;
                                }
                                phdr = phdrs.get(self.cur_phdr).unwrap();
                            }
                            let bytes_left = phdr.p_filesz - self.seg_pos;
                            let mut write_len = DATA_REGION_SIZE;
                            if bytes_left < DATA_REGION_SIZE {
                                write_len = bytes_left;
                            }
                            //Offset is kernel file offset plus last position in segment
                            let pos = phdr.p_offset + self.seg_pos;
                            //Seek to offset in segment

                            //Write segment bytes to data region
                            mem.write_slice(
                                    &mut self.kernel[pos as usize..][..write_len as usize],
                                    GuestAddress(DATA_REGION_ADDR),
                                )
                                .unwrap();
                            //Update position in current segment
                            self.seg_pos += write_len;

                            //If we finished writing the segment, move to the next one
                            if self.seg_pos >= phdr.p_filesz {
                                self.cur_phdr += 1;
                                self.seg_pos = 0;
                            }
                        } else {
                            warn!("No program headers");
                        }
                    } else {
                        warn!("Invalid state");
                    }
                }
                Some(Command::ElfRela) => {
                    let mut output = Vec::new();

                    // Dynamic Symbols
                    output.extend_from_slice(
                        &(self.dyn_syms.len() as u64).to_le_bytes()
                    );

                    let mut dyn_sym_slice = [0u8; sym64::SIZEOF_SYM];
                    for sym in self.dyn_syms.iter() {
                        sym.try_into_ctx(&mut dyn_sym_slice, Endian::Little).expect("failed to serialize symbol");
                        output.extend_from_slice(&dyn_sym_slice);
                    }

                    // Relocations
                    output.extend_from_slice(
                        &(self.rela.len() as u64).to_le_bytes()
                    );

                    let mut rela_slice = [0u8; reloc64::SIZEOF_RELA];
                    for reloc in self.rela.iter() {
                        reloc.try_into_ctx(&mut rela_slice, Endian::Little).expect("failed to serialize reloc");
                        output.extend_from_slice(&rela_slice);
                    }


                    if output.len() > DATA_REGION_SIZE as usize {
                        panic!("too many relocations!");
                    }

                    self.mem()
                        .write_slice(&output, GuestAddress(DATA_REGION_ADDR))
                        .unwrap();

                }
                Some(Command::ElfDynSym) => {
                    /* let mut output = Vec::new();
                    output.extend_from_slice(
                        &(self.dyn_syms.len() as u64).to_le_bytes()
                    );

                    let dyn_sym_slice = [0u8; sym64::SIZEOF_SYM];
                    for sym in self.dyn_syms.iter() {
                        sym.try_into_ctx(&mut output, Endian::Little).expect("failed to serialize symbol");
                        output.extend_from_slice(&dyn_sym_slice);
                    }

                    if output.len() > DATA_REGION_SIZE as usize {
                        panic!("too many dynamic symbols!");
                    }

                    self.mem
                        .write_slice(&output, GuestAddress(DATA_REGION_ADDR))
                        .unwrap(); */
                    unimplemented!()
                }
                // Some(Command::BzImageLen) => {
                //     if self.state == State::WriteBzImageLen {
                //         let len_buf = u32::to_le_bytes(self.kernel_len as u32);
                //         data.copy_from_slice(&len_buf);
                //         self.state = State::WriteBzImageData;
                //     } else {
                //         warn!("Invalid state");
                //     }
                // }
                // Some(Command::BzimageData) => {
                //     if self.state == State::WriteBzImageData {
                //         let pos = self.kernel.stream_position().unwrap();
                //         let mut chunk_sz = DATA_REGION_SIZE;
                //         //check if the last chunk of file is less than a page
                //         if self.kernel_len - pos < DATA_REGION_SIZE {
                //             chunk_sz = self.kernel_len - pos;
                //         }

                //         self.mem
                //             .read_exact_from(
                //                 GuestAddress(DATA_REGION_ADDR),
                //                 &mut self.kernel,
                //                 chunk_sz as usize,
                //             )
                //             .unwrap();
                //     }
                // }
                _ => warn!("Invalid read for command"),
            }
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        //Only allow writes to 8 bytes before the page to load data
        if offset != 0 || data.len() < 1 {
            info!("fw_cfg invalid write");
        } else {
            let mut buf: [u8; 1] = Default::default();
            buf.copy_from_slice(&data[0..]);
            let code = u8::from_le_bytes(buf);
            let result = Command::try_from(code);
            match result {
                Ok(cmd) => {
                    self.cmd = Some(cmd);
                    info!("FW_CFG: {:?}", self.cmd);
                }
                _ => warn!("FwCfg invalid command"),
            }
        };

        None
    }
}

fn get_kernel_type<F>(kernel_image: &mut F) -> KernelType
where
    F: ReadVolatile + Seek,
{
    let mut kernel_type = KernelType::Direct;
    //determine if kernel file is bzImage or uncompressed
    //Assume bzImage first
    let mut bz_header = setup_header::default();
    kernel_image
        .seek(SeekFrom::Start(BZIMAGE_HEADER_OFFSET))
        .unwrap();

    bz_header
        .as_bytes()
        .read_volatile_from(0, kernel_image, mem::size_of::<setup_header>())
        .unwrap();

    if bz_header.header == BZIMAGE_HEADER_MAGIC {
        kernel_type = KernelType::BzImage;
    }

    kernel_type
}
