import numbat

import surfactant.plugin
from surfactant.sbomtypes import SBOM


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    db = numbat.SourcetrailDB.open(outfile.name, clear=True)
    soft_ids = {}
    for soft in sbom.software:
        if soft.name:
            soft_id = db.record_class(name=soft.name)
        elif len(soft.fileName) > 0:
            soft_id = db.record_class(name=soft.fileName[0])
        else:
            continue
        soft_ids[soft.UUID] = soft_id
        for path in soft.installPath:
            db.record_field(name=path, parent_id=soft_id)
        for name in soft.fileName:
            db.record_method(name=name, parent_id=soft_id)
        for meta in soft.metadata:
            if "installPathSymlinks" in meta:
                for path in meta["installPathSymlinks"]:
                    typedef_id = db.record_typedef_node(name=path)
                    db.record_ref_usage(typedef_id, soft_id)
            if "fileNameSymlinks" in meta:
                for path in meta["fileNameSymlinks"]:
                    typedef_id = db.record_typedef_node(name=path)
                    db.record_ref_usage(typedef_id, soft_id)
    for relation in sbom.relationships:
        if relation.relationship == "Uses":
            db.record_ref_usage(soft_ids[relation.xUUID], soft_ids[relation.yUUID])
    db.commit()
    db.close()


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    return "sourcetrail_db"
