# CyTRICS Single-Page SBOM Editor

This is a single-file, browser-based SBOM HTML editor.

## PURL builder placement

The PURL builder remains collapsed by default. After selecting a software entry and clicking **Build Related PURL**, the builder opens immediately below the entry title/action row and above the editable software fields. Selecting another software entry closes it automatically.

## How to use

1. Open `sbom-workbench.html` in a browser.
2. Load a CyTRICS JSON SBOM.
3. Search the software section by filename, product name, UUID, SHA-1, SHA-256, MD5, install path, or PURL.
4. Select a source software/file entry.
5. Use **Create related PURL component** to manually build a Package URL.
6. Click **Create software entry + relationship**.
7. Export the updated SBOM.

## What the PURL action does

For the selected source software entry, the tool creates a new CyTRICS `software[]` component:

- `UUID`: newly generated UUID
- `softwareType`: `["software package"]`
- `name[]`: includes a product name and a `package URL (purl)` entry
- `version`: the manually entered PURL version, if provided
- `notHashable`: `true`
- `relationshipAssertion`: `Root`

It also creates a new `relationships[]` entry:

- `xUUID`: selected source file/software UUID
- `yUUID`: newly generated PURL software UUID
- `relationship`: selected relationship value, such as `Uses`, `Contains`, `Downloads`, or `Mounted on`

## Notes

- The full software list is intentionally not rendered until you search, which is better for large SBOMs.
- Export normalizes the document toward CyTRICS 1.0.1 shape and removes legacy top-level fields such as `properties`, `systems`, `analysisData`, `observations`, and `starRelationships`.
- This single page uses CDN-hosted React/Babel dependencies like the uploaded HTML prototype, so it needs browser access to those CDNs unless you vendor the dependencies locally.


