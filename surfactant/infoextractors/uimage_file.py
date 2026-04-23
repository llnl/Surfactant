# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# Extracts information on U-Boot/uImage files
# https://github.com/u-boot/u-boot/blob/master/include/image.h
# https://github.com/u-boot/u-boot/blob/master/boot/image.c

import struct

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

# Compression types is not a tuple because (other than none), the id, short name, and message more or less match
COMPRESSION_TYPES = {
    0: "None",
    1: "gzip",
    2: "bzip2",
    3: "lzma",
    4: "lzo",
    5: "lz4",
    6: "zstd",
}

# Operating System Code (IH_OS_id, short name, long name/description)
OPERATING_SYSTEMS = {
    0: ("INVALID", "invalid", "Invalid OS"),
    1: ("OPENBSD", "openbsd", "OpenBSD"),
    2: ("NETBSD", "netbsd", "NetBSD"),
    3: ("FREEBSD", "freebsd", "FreeBSD"),
    4: ("4_4BSD", "4_4bsd", "4_4BSD"),  # not sure if long description should be 4.4BSD
    5: ("LINUX", "linux", "Linux"),
    6: ("SVR4", "svr4", "SVR4"),
    7: ("ESIX", "esix", "Esix"),
    8: ("SOLARIS", "solaris", "Solaris"),
    9: ("IRIX", "irix", "Irix"),
    10: ("SCO", "sco", "SCO"),
    11: ("DELL", "dell", "Dell"),
    12: ("NCR", "ncr", "NCR"),
    13: ("LYNXOS", "lynxos", "LynxOS"),  # short/long name mapping table is missing this one
    14: ("VXWORKS", "vxworks", "VxWorks"),
    15: ("PSOS", "psos", "pSOS"),
    16: ("QNX", "qnx", "QNX"),
    17: ("U_BOOT", "u-boot", "U-Boot"),
    18: ("RTEMS", "rtems", "RTEMS"),
    19: ("ARTOS", "artos", "ARTOS"),  # short/long name mapping table is missing this one
    20: ("UNITY", "unity", "Unity OS"),  # short/long name mapping table is missing this one
    21: ("INTEGRITY", "integrity", "INTEGRITY"),
    22: ("OSE", "ose", "Enea OSE"),
    23: ("PLAN9", "plan9", "Plan 9"),
    24: ("OPENRTOS", "openrtos", "OpenRTOS"),
    25: ("ARM_TRUSTED_FIRMWARE", "arm-trusted-firmware", "ARM Trusted Firmware"),
    26: ("TEE", "tee", "Trusted Execution Environment"),
    27: ("OPENSBI", "opensbi", "RISC-V OpenSBI"),
    28: ("EFI", "efi", "EFI Firmware"),
    29: ("ELF", "elf", "ELF Image"),
}

# CPU Architecture Code (supported by Linux) tuples (IH_ARCH_id, short name, long name/description)
ARCHITECTURES = {
    0: ("INVALID", "invalid", "Invalid ARCH"),
    1: ("ALPHA", "alpha", "Alpha"),
    2: ("ARM", "arm", "ARM"),
    3: ("I386", "x86", "Intel x86"),
    4: ("IA64", "ia64", "IA64"),
    5: ("MIPS", "mips", "MIPS"),
    6: ("MIPS64", "mips64", "MIPS 64 Bit"),
    7: ("PPC", "powerpc", "PowerPC"),  # also has an alias short name of ppc
    8: ("S390", "s390", "IBM S390"),
    9: ("SH", "sh", "SuperH"),
    10: ("SPARC", "sparc", "SPARC"),
    11: ("SPARC64", "sparc64", "SPARC 64 Bit"),
    12: ("M68K", "m68k", "M68K"),
    13: ("NIOS", "nios", "Nios-32"),  # short/long name mapping table is missing this one
    14: ("MICROBLAZE", "microblaze", "MicroBlaze"),
    15: ("NIOS2", "nios2", "NIOS II"),
    16: ("BLACKFIN", "blackfin", "Blackfin"),
    17: ("AVR32", "avr32", "AVR32"),
    18: (
        "ST200",
        "st200",
        "STMicroelectronics ST200",
    ),  # short/long name mapping table is missing this one
    19: ("SANDBOX", "sandbox", "Sandbox"),  # test only
    20: ("NDS32", "nds32", "NDS32"),
    21: ("OPENRISC", "or1k", "OpenRISC 1000"),
    22: ("ARM64", "arm64", "AArch64"),
    23: ("ARC", "arc", "ARC"),
    24: ("X86_64", "x86_64", "AMD x86_64"),
    25: ("XTENSA", "xtensa", "Xtensa"),
    26: ("RISCV", "riscv", "RISC-V"),
}

# Image type tuples (IH_TYPE_id, short name, long name/description)
# Summary of Image Types:
#  - Standalone Programs: Directly runnable in the environment provided by U-Boot; can return control to U-Boot.
#  - OS Kernel Images: Images of embedded OS that take over control completely; cannot re-enter U-Boot except by resetting the CPU.
#  - RAMDisk Images: Data blocks whose parameters are passed to an OS kernel being started.
#  - Multi-File Images: Contain several images (e.g., OS kernel and RAMDisks); useful for booting over the network.
#  - Firmware Images: Binary images containing firmware (e.g., U-Boot or FPGA images) usually programmed to flash memory.
#  - Script Files: Command sequences executed by U-Boot's command interpreter; useful for shell scripts.
IMAGE_TYPES = {
    0: ("INVALID", "invalid", "Invalid Image"),
    1: ("STANDALONE", "standalone", "Standalone Program"),
    2: ("KERNEL", "kernel", "Kernel Image"),
    3: ("RAMDISK", "ramdisk", "RAMDisk Image"),
    4: ("MULTI", "multi", "Multi-File Image"),
    5: ("FIRMWARE", "firmware", "Firmware"),
    6: ("SCRIPT", "script", "Script"),
    7: ("FILESYSTEM", "filesystem", "Filesystem Image"),
    8: ("FLATDT", "flat_dt", "Flat Device Tree"),
    9: ("KWBIMAGE", "kwbimage", "Kirkwood Boot Image"),
    10: ("IMXIMAGE", "imximage", "Freescale i.MX Boot Image"),
    11: ("UBLIMAGE", "ublimage", "Davinci UBL Image"),
    12: ("OMAPIMAGE", "omapimage", "TI OMAP SPL with GP CH"),
    13: ("AISIMAGE", "aisimage", "Davinci AIS Image"),
    14: ("KERNEL_NOLOAD", "kernel_noload", "Kernel Image (no loading done)"),
    15: ("PBLIMAGE", "pblimage", "Freescale PBL Boot Image"),
    16: ("MXSIMAGE", "mxsimage", "Freescale MXS Boot Image"),
    17: ("GPIMAGE", "gpimage", "TI Keystone SPL Image"),
    18: ("ATMELIMAGE", "atmelimage", "ATMEL ROM-Boot Image"),
    19: ("SOCFPGAIMAGE", "socfpgaimage", "Altera SOCFPGA CV/AV preloader"),
    20: ("X86_SETUP", "x86_setup", "x86 setup.bin"),
    21: (
        "LPC32XXIMAGE",
        "lpc32xximage",
        "LPC32XX Boot Image",
    ),  # image.h for u-boot has incorrect comment on this line
    22: ("LOADABLE", "", "A list of typeless images"),
    23: ("RKIMAGE", "rkimage", "Rockchip Boot Image"),
    24: ("RKSD", "rksd", "Rockchip SD Boot Image"),
    25: ("RKSPI", "rkspi", "Rockchip SPI Boot Image"),
    26: ("ZYNQIMAGE", "zynqimage", "Xilinx Zynq Boot Image"),
    27: ("ZYNQMPIMAGE", "zynqmpimage", "Xilinx ZynqMP Boot Image"),
    28: ("ZYNQMPBIF", "zynqmpbif", "Xilinx ZynqMP Boot Image (bif)"),
    29: ("FPGA", "fpga", "FPGA Image"),
    30: ("VYBRIDIMAGE", "vybridimage", "Vybrid Boot Image"),  # .vyb
    31: ("TEE", "tee", "Trusted Execution Environment Image"),
    32: ("FIRMWARE_IVT", "firmware_ivt", "Firmware with HABv4 IVT"),
    33: ("PMMC", "pmmc", "TI Power Management Micro-Controller Firmware"),
    34: ("STM32IMAGE", "stm32image", "STMicroelectronics STM32 Image"),
    35: ("SOCFPGAIMAGE_V1", "socfpgaimage_v1", "Altera SOCFPGA A10 preloader"),
    36: ("MTKIMAGE", "mtk_image", "MediaTek BootROM loadable Image"),
    37: ("IMX8MIMAGE", "imx8mimage", "NXP i.MX8M Boot Image"),
    38: ("IMX8IMAGE", "imx8image", "NXP i.MX8 Boot Image"),
    39: ("COPRO", "copro", "Coprocessor Image"),
    40: ("SUNXI_EGON", "sunxi_egon", "Allwinner eGON Boot Image"),
    41: ("SUNXI_TOC0", "sunxi_toc0", "Allwinner TOC0 Boot Image"),
    42: ("FDT_LEGACY", "fdt_legacy", "Legacy Image with Flat Device Tree"),
    43: ("RENESAS_SPKG", "spkgimage", "Renesas SPKG Image"),
    44: ("STARFIVE_SPL", "sfspl", "StarFive SPL Image"),
    45: ("TFA_BL31", "tfa-bl31", "TFA BL31 Image"),
}

# Phase that the image is intended for
# Combined with image type for composite type (but appears to not be used in legacy u-boot header)
IMAGE_PHASES = {
    0: ("NONE", "none", "any"),
    1: ("U_BOOT", "u-boot", "U-Boot phase"),
    2: ("SPL", "spl", "SPL Phase"),
}


def _parse_uimage_header(fname: str) -> dict:
    # Image header is 64 bytes
    # struct layout (big-endian):
    # magic(4), header_crc(4), timestamp(4), size(4), load(4), ep(4), data_crc(4),
    # os(1), arch(1), im_type(1), comp_type(1), name(32)
    with open(fname, "rb") as f:
        data = f.read(64)
    try:
        (
            _magic,
            header_crc,
            timestamp,
            data_size,
            load_addr,
            entry_point,
            data_crc,
            os_type,
            arch,
            image_type,
            compression_type,
        ) = struct.unpack(">IIIIIIIBBBB", data[:32])
    except struct.error as e:
        logger.warning(f"Error unpacking uImage header in file {fname}")
        raise ValueError(f"Error unpacking uImage header in file {fname}") from e
    image_name = data[32:64].rstrip(b"\x00").decode("ascii", errors="replace")

    # for multi (or script?) type images, go to data right after header; count non-zero array uint32_t sizes to get number of parts
    # image data starts at start_data + (count+1)*sizeof(uint32_t) to account for last null entry
    # sizes are stored in the file as big endian, and are the size for the given component
    # to find data offset for a particular component index, add up each preceeding component size rounded up to 4-bytes: offset += (uimage_to_cpu(size[i]) + 3) & ~3 ;

    # Related image types are fit/fdt, and Android... need to investigate if they will have the legacy u-boot header or not
    # could be that fdt image header is nested in data section only when image type is FDT_LEGACY
    # fit/fdt images, may be possible to check for fdt header magic 0xd00dfeed
    # Android boot magic is "ANDROID!"
    return {
        "header_crc": hex(header_crc),
        "timestamp": timestamp,
        "data_size": data_size,
        "load_addr": hex(load_addr),
        "entry_point": hex(entry_point),
        "data_crc": hex(data_crc),
        "os": OPERATING_SYSTEMS.get(os_type, (str(os_type), "", ""))[0],
        "os_description": OPERATING_SYSTEMS.get(os_type, ("", "", "Unknown OS"))[2],
        "arch": ARCHITECTURES.get(arch, (str(arch), "", ""))[0],
        "arch_description": ARCHITECTURES.get(arch, ("", "", "Unknown Architecture"))[2],
        "image_type": IMAGE_TYPES.get(image_type, (str(image_type), "", ""))[0],
        "image_type_description": IMAGE_TYPES.get(image_type, ("", "", "Unknown Image"))[2],
        "compression_type": COMPRESSION_TYPES.get(compression_type, str(compression_type)),
        "name": image_name,
    }


def supports_file(filetype: list[str]) -> bool:
    return "UIMAGE" in filetype


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
    software_field_hints: list[tuple[str, object, int]],
) -> object:
    if not supports_file(filetype):
        return None
    try:
        uimage_header = _parse_uimage_header(filename)
        if "name" in uimage_header:
            software_field_hints.append(("name", uimage_header["name"], 40))
        return {"uimage_header": uimage_header}
    except ValueError as e:
        return None
