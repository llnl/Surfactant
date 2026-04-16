import click

from surfactant.configmanager import ConfigManager
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager


@click.command("stat")
@click.argument("input_sbom", type=click.File("r"), required=True)
@click.option(
    "--input_format",
    is_flag=False,
    default=ConfigManager().get(
        "core", "input_format", fallback="surfactant.input_readers.cytrics_reader"
    ),
    help="SBOM input format, options=[cytrics|cyclonedx|spdx]",
)
def stat(input_sbom, input_format):
    """Print simple statistics about a SBOM."""
    pm = get_plugin_manager()
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    data = input_reader.read_sbom(input_sbom)

    elf_is_lib = 0
    elf_is_exe = 0
    pe_is_exe = 0
    pe_is_dll = 0
    clr_exe = 0
    clr_dll = 0
    for sw in data.software:
        if not sw.metadata:
            continue

        elf_is_lib_sw = any(isinstance(md, dict) and md.get("elfIsLib") for md in sw.metadata)
        elf_is_exe_sw = any(isinstance(md, dict) and md.get("elfIsExe") for md in sw.metadata)
        pe_is_exe_sw = any(isinstance(md, dict) and md.get("peIsExe") for md in sw.metadata)
        pe_is_dll_sw = any(isinstance(md, dict) and md.get("peIsDll") for md in sw.metadata)
        pe_is_clr_sw = any(isinstance(md, dict) and md.get("peIsClr") for md in sw.metadata)

        if elf_is_lib_sw:
            elf_is_lib += 1
        if elf_is_exe_sw:
            elf_is_exe += 1
        if pe_is_exe_sw:
            pe_is_exe += 1
        if pe_is_dll_sw:
            pe_is_dll += 1
        if pe_is_clr_sw and pe_is_exe_sw:
            clr_exe += 1
        elif pe_is_clr_sw and pe_is_dll_sw:
            clr_dll += 1

    num_pe_exe_str = f"Number of PE Executables: {pe_is_exe} with {clr_exe} using .NET/CLR"
    num_dll_str = f"Number of DLLs: {pe_is_dll} with {clr_dll} using .NET/CLR"
    num_elf_bin_str = f"Number of ELF Binaries: {elf_is_exe}"
    num_elf_shared_lib_str = f"Number of ELF shared libraries: {elf_is_lib}"

    click.echo(num_pe_exe_str)
    click.echo(num_dll_str)
    click.echo(num_elf_bin_str)
    click.echo(num_elf_shared_lib_str)
