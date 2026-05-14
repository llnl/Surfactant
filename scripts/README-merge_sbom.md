Use the main Surfactant `merge` command for the supported merge workflow. The
`merge_sbom.py` script remains a direct CyTRICS-only merge helper when the input
files are already valid CyTRICS SBOM JSON files.

`ls -d ~/Folder_With_SBOMs/Surfactant-* | xargs -d '\n' python3.8 merge_sbom.py --sbom_outfile combined_sbom.json`

The current `merge_sbom.py` script requires Surfactant to be importable in the
Python environment. It only accepts input SBOM paths and `--sbom_outfile`. It
no longer supports `--config_file`, and it no longer creates a top-level system
entry. Each input is loaded through `SBOM.from_json(...)`, merged with
`SBOM.merge(...)`, and written back out as schema-validated CyTRICS JSON using
`SBOM.to_json(...)`.
