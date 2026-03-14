# Copyright 2026 Veritensor Security Apache 2.0
# Generates Software Bill of Materials (SBOM) in CycloneDX format.

from typing import List
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model import Property 
from cyclonedx.output.json import JsonV1Dot5
from veritensor.core.types import ScanResult

def generate_sbom(results: List[ScanResult]) -> str:
    bom = Bom()
    
    for res in results:
        comp_type = ComponentType.MACHINE_LEARNING_MODEL
        name = res.file_path
        
        component = Component(name=name, type=comp_type, bom_ref=name)
        
        if res.file_hash:
            component.hashes.add(HashType(alg=HashAlgorithm.SHA_256, content=res.file_hash))
            
        # We use Property objects instead of strings
        component.properties.add(Property(name="veritensor:status", value=res.status))
        component.properties.add(Property(name="veritensor:verified", value=str(res.identity_verified).lower()))
        
        if res.threats:
            component.properties.add(Property(name="veritensor:threats", value="; ".join(res.threats)))

        bom.components.add(component)

    outputter = JsonV1Dot5(bom)
    return outputter.output_as_string()