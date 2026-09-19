import csv
import io

import pytest

from surfactant.output.csv_writer import write_sbom
from surfactant.sbomtypes import SBOM, Software

CONTAINER_UUID = "12345678-1234-4234-9234-123456789abc"


def _csv_paths(software):
    output = io.StringIO()
    write_sbom(SBOM(software=[software]), output)
    return [row["Path"] for row in csv.DictReader(io.StringIO(output.getvalue()))]


@pytest.mark.parametrize(
    "paths",
    [
        ["app"],
        ["usr/lib/libexample.so"],
        ["/usr/bin/app"],
        ["ab/c.txt", "a/bc.txt"],
        ["Program Files/Example, Inc./app.exe"],
    ],
    ids=["flat", "nested", "absolute", "distinct-paths", "csv-quoting"],
)
def test_csv_preserves_container_path_separators(paths):
    software = Software(
        sha256="a" * 64,
        fileName=["fallback"],
        containerPath=[f"{CONTAINER_UUID}/{path}" for path in paths],
    )

    assert _csv_paths(software) == paths


@pytest.mark.parametrize("use_install_path", [True, False])
def test_csv_retains_install_path_and_filename_fallbacks(use_install_path):
    software = Software(
        sha256="a" * 64,
        fileName=["app"],
        installPath=["/opt/example/app"] if use_install_path else [],
        containerPath=[f"{CONTAINER_UUID}/usr/bin/app"] if use_install_path else [],
    )

    expected = ["/opt/example/app"] if use_install_path else ["app"]
    assert _csv_paths(software) == expected
