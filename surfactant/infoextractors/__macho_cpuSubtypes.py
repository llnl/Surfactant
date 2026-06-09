# Things related to Mach-O cpu type and subtypes, pulled from:
# - https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/MachO.h
# - MacOSX14.4.sdk/usr/include/mach/machine.h (located in /Library/Developer/CommandLineTools/SDKs/ on macOS)

from enum import IntEnum

CPU_ARCH_MASK = 0xFF000000  # Mask for architecture bits
CPU_ARCH_ABI64 = 0x01000000  # 64 bit ABI
CPU_ARCH_ABI64_32 = 0x02000000  # ILP32 ABI on 64-bit hardware


# original #define for cpu types in MacOS SDK start with CPU_TYPE_
# original #define for cpu sybtypes in MacOS SDK start with CPU_SUBTYPE_
class CPU_Type(IntEnum):
    ANY = -1
    VAX = 1
    MC680x0 = 6
    X86 = 7
    I386 = X86  # compatibility
    X86_64 = X86 | CPU_ARCH_ABI64
    MIPS = 8
    MC98000 = 10  # Old Motorola PowerPC
    HPPA = 11
    ARM = 12
    ARM64 = ARM | CPU_ARCH_ABI64
    ARM64_32 = ARM | CPU_ARCH_ABI64_32
    MC88000 = 13
    SPARC = 14
    I860 = 15
    ALPHA = 16
    POWERPC = 18
    POWERPC64 = POWERPC | CPU_ARCH_ABI64


CPU_SUBTYPE_MASK = 0xFF000000  # Mask for feature flags
CPU_SUBTYPE_LIB64 = 0x80000000  # 64 bit libraries
CPU_SUBTYPE_PTRAUTH_ABI = 0x80000000  # pointer authentication with versioned ABI


class cpuSubtype_VAX(IntEnum):
    VAX_ALL = 0
    VAX780 = 1
    VAX785 = 2
    VAX750 = 3
    VAX730 = 4
    UVAXI = 5
    UVAXII = 6
    VAX8200 = 7
    VAX8500 = 8
    VAX8600 = 9
    VAX8650 = 10
    VAX8800 = 11
    UVAXIII = 12


class cpuSubtype_MC680x0(IntEnum):
    MC680x0_ALL = 1
    MC68030 = MC680x0_ALL
    MC68040 = 2
    MC68030_ONLY = 3


def CPU_SUBTYPE_INTEL(f, m):
    return f + (m << 4)


def CPU_SUBTYPE_INTEL_FAMILY(x):
    return x & 15


def CPU_SUBTYPE_INTEL_MODEL(x):
    return x >> 4


class cpuSubtype_I386(IntEnum):
    I386_ALL = CPU_SUBTYPE_INTEL(3, 0)
    _386 = I386_ALL
    _486 = CPU_SUBTYPE_INTEL(4, 0)
    _486SX = CPU_SUBTYPE_INTEL(4, 8)
    PENT = CPU_SUBTYPE_INTEL(5, 0)
    _586 = PENT
    PENTPRO = CPU_SUBTYPE_INTEL(6, 1)
    PENTII_M3 = CPU_SUBTYPE_INTEL(6, 3)
    PENTII_M5 = CPU_SUBTYPE_INTEL(6, 5)
    CELERON = CPU_SUBTYPE_INTEL(7, 6)
    CELERON_MOBILE = CPU_SUBTYPE_INTEL(7, 7)
    PENTIUM_3 = CPU_SUBTYPE_INTEL(8, 0)
    PENTIUM_3_M = CPU_SUBTYPE_INTEL(8, 1)
    PENTIUM_3_XEON = CPU_SUBTYPE_INTEL(8, 2)
    PENTIUM_M = CPU_SUBTYPE_INTEL(9, 0)
    PENTIUM_4 = CPU_SUBTYPE_INTEL(10, 0)
    PENTIUM_4_M = CPU_SUBTYPE_INTEL(10, 1)
    ITANIUM = CPU_SUBTYPE_INTEL(11, 0)
    ITANIUM_2 = CPU_SUBTYPE_INTEL(11, 1)
    XEON = CPU_SUBTYPE_INTEL(12, 0)
    XEON_MP = CPU_SUBTYPE_INTEL(12, 1)


class cpuSubtype_X86(IntEnum):
    X86_ALL = 3
    X86_64_ALL = 3
    X86_64_ARCH1 = 4
    X86_64_H = 8  # Haswell feature subset


class cpuSubtype_MIPS(IntEnum):
    MIPS_ALL = 0
    MIPS_R2300 = 1
    MIPS_R2600 = 2
    MIPS_R2800 = 3
    MIPS_R2000a = 4  # pmax
    MIPS_R2000 = 5
    MIPS_R3000a = 6  # 3max
    MIPS_R3000 = 7


class cpuSubtype_MC98000(IntEnum):
    MC980000_ALL = 0
    MC98601 = 1


# Hewlett-Packard HP-PA processors
class cpuSubtype_HPPA(IntEnum):
    HPPA_ALL = 0
    HPPA_7100 = HPPA_ALL  # compatibility
    HPPA_7100LC = 1


class cpuSubtype_MC88000(IntEnum):
    MC88000_ALL = 0
    MC88100 = 1
    MC88110 = 2


class cpuSubtype_SPARC(IntEnum):
    SPARC_ALL = 0


class cpuSubtype_I860(IntEnum):
    I860_ALL = 0
    I860_860 = 1


class cpuSubtype_PowerPC(IntEnum):
    POWERPC_ALL = 0
    POWERPC_601 = 1
    POWERPC_602 = 2
    POWERPC_603 = 3
    POWERPC_603e = 4
    POWERPC_603ev = 5
    POWERPC_604 = 6
    POWERPC_604e = 7
    POWERPC_620 = 8
    POWERPC_750 = 9
    POWERPC_7400 = 10
    POWERPC_7450 = 11
    POWERPC_970 = 100


class cpuSubtype_ARM(IntEnum):
    ARM_ALL = 0
    ARM_V4T = 5
    ARM_V6 = 6
    ARM_V5TEJ = 7  # also ARM_V5TEJ
    ARM_XSCALE = 8
    ARM_V7 = 9  # ARMv7-A and ARMv7-R
    ARM_V7F = 10  # Cortex A8
    ARM_V7S = 11  # Swift
    ARM_V7K = 12
    ARM_V8 = 13
    ARM_V6M = 14
    ARM_V7M = 15
    ARM_V7EM = 16
    ARM_V8M = 17


class cpuSubtype_ARM64(IntEnum):
    ARM64_ALL = 0
    ARM64_V8 = 1
    ARM64E = 2


class cpuSubtype_ARM64_32(IntEnum):
    ARM64_32_ALL = 0
    ARM64_32_V8 = 1


def get_cpu_subtype_name(cpuType: CPU_Type, cpuSubtype) -> str:
    cpu_subtype_mapping = {
        CPU_Type.VAX: cpuSubtype_VAX,
        CPU_Type.MC680x0: cpuSubtype_MC680x0,
        CPU_Type.X86: cpuSubtype_I386,
        CPU_Type.X86_64: cpuSubtype_X86,
        CPU_Type.MIPS: cpuSubtype_MIPS,
        CPU_Type.MC98000: cpuSubtype_MC98000,
        CPU_Type.HPPA: cpuSubtype_HPPA,
        CPU_Type.ARM: cpuSubtype_ARM,
        CPU_Type.ARM64: cpuSubtype_ARM64,
        CPU_Type.ARM64_32: cpuSubtype_ARM64_32,
        CPU_Type.MC88000: cpuSubtype_MC88000,
        CPU_Type.SPARC: cpuSubtype_SPARC,
        CPU_Type.I860: cpuSubtype_I860,
        CPU_Type.POWERPC: cpuSubtype_PowerPC,
        CPU_Type.POWERPC64: cpuSubtype_PowerPC,  # Does PowerPC64 use the same subtypes as PowerPC?
    }

    subtype_enum = cpu_subtype_mapping.get(cpuType)

    if subtype_enum is None:
        return "UNKNOWN"

    try:
        return subtype_enum(cpuSubtype).name
    except ValueError:
        return "UNKNOWN"


def get_cpu_type_name(cpuType: CPU_Type) -> str:
    if isinstance(cpuType, int):
        try:
            cpuType = CPU_Type(cpuType)
        except ValueError:
            return "UNKNOWN"

    if isinstance(cpuType, CPU_Type):
        return cpuType.name
    return "UNKNOWN"
