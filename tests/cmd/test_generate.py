import json
import queue
from pathlib import Path
from types import SimpleNamespace

import click
import pytest

from surfactant.cmd.generate import get_software_entry, sbom
from surfactant.sbomtypes import SBOM
from tests.cmd import common

testing_data = Path(Path(__file__).parent.parent, "data")


def test_generate_no_install_prefix(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"]}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    # the click.testing module would be better here but it doesn't allow for files to be generated
    # pylint: disable=no-value-for-parameter
    sbom([config_path, output_path], standalone_mode=False)
    # pylint: enable

    common.test_generate_result_no_install_prefix(output_path, extract_path)


def test_generate_with_install_prefix(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"], "installPrefix": "test_prefix/"}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    # the click.testing module would be better here but it doesn't allow for files to be generated
    # pylint: disable=no-value-for-parameter
    sbom([config_path, output_path], standalone_mode=False)
    # pylint: enable

    with open(output_path) as f:
        generated_sbom = json.load(f)

    assert len(generated_sbom["software"]) == 2

    expected_software_names = {"hello_world.exe", "testlib.dll"}
    actual_software_names = {software["fileName"][0] for software in generated_sbom["software"]}
    assert expected_software_names == actual_software_names

    expected_install_paths = {
        "hello_world.exe": "test_prefix/hello_world.exe",
        "testlib.dll": "test_prefix/testlib.dll",
    }
    for software in generated_sbom["software"]:
        assert software["installPath"][0] == expected_install_paths[software["fileName"][0]]

    uuids = {software["fileName"][0]: software["UUID"] for software in generated_sbom["software"]}
    assert len(generated_sbom["relationships"]) == 1
    assert generated_sbom["relationships"][0] == {
        "xUUID": uuids["hello_world.exe"],
        "yUUID": uuids["testlib.dll"],
        "relationship": "Uses",
    }


def test_generate_with_author(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"]}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    # pylint: disable=no-value-for-parameter
    sbom(
        [
            "--author_name",
            "Lawrence Livermore National Laboratory",
            "--author_type",
            "organization",
            config_path,
            output_path,
        ],
        standalone_mode=False,
    )
    # pylint: enable

    with open(output_path) as f:
        generated_sbom = json.load(f)

    assert generated_sbom["authors"] == [
        {
            "authorType": "organization",
            "authorName": "Lawrence Livermore National Laboratory",
        }
    ]


def test_get_software_entry_merges_software_type_hints(tmp_path):
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"sample")

    def extract_file_info(**kwargs):
        kwargs["software_field_hints"].extend(
            [
                ("softwareType", "application", 10),
                ("softwareType", ["library", "application"], 5),
                ("softwareType", ("firmware",), 1),
            ]
        )
        return []

    pluginmanager = SimpleNamespace(hook=SimpleNamespace(extract_file_info=extract_file_info))

    software, children = get_software_entry(
        queue.Queue(),
        None,
        pluginmanager,
        SBOM(),
        sample_path.as_posix(),
        filetype=[],
    )

    assert not children
    assert software.softwareType == ["application", "library", "firmware"]


def test_generate_author_requires_name_and_type(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"]}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    with pytest.raises(click.ClickException, match="--author_name and --author_type"):
        # pylint: disable=no-value-for-parameter
        sbom(
            [
                "--author_name",
                "Lawrence Livermore National Laboratory",
                config_path,
                output_path,
            ],
            standalone_mode=False,
        )
        # pylint: enable


def test_generate_with_skip_install_path(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"]}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    # the click.testing module would be better here but it doesn't allow for files to be generated
    # pylint: disable=no-value-for-parameter
    sbom(["--skip_install_path", config_path, output_path], standalone_mode=False)
    # pylint: enable

    with open(output_path) as f:
        generated_sbom = json.load(f)

    assert len(generated_sbom["software"]) == 2

    expected_software_names = {"hello_world.exe", "testlib.dll"}
    actual_software_names = {software["fileName"][0] for software in generated_sbom["software"]}
    assert expected_software_names == actual_software_names

    for software in generated_sbom["software"]:
        assert software["installPath"] == []

    assert len(generated_sbom["relationships"]) == 0


def test_generate_with_conflicting_install_prefixs(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"], "installPrefix": "config_prefix/"}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    with pytest.raises(SystemExit) as exec_info:
        # pylint: disable=no-value-for-parameter
        sbom(
            [config_path, output_path, "--install_prefix", "cmdline_prefix/"], standalone_mode=False
        )
        # pylint: enable

    assert isinstance(exec_info.value.code, int) and exec_info.value.code < 0
