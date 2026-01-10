# Copyright 2025 Veritensor Security
# Generates Software Bill of Materials (SBOM) in CycloneDX format.

from typing import List
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.output.json import JsonV1Dot5
from veritensor.core.types import ScanResult

def generate_sbom(results: List[ScanResult]) -> str:
    """
    Creates a CycloneDX SBOM containing all scanned models.
    """
    bom = Bom()
    
    for res in results:
        # Determine component type (Machine Learning Model is supported in CDX 1.5)
        # If the library is older, it might fall back to 'file' or 'library'
        comp_type = ComponentType.MACHINE_LEARNING_MODEL
        
        name = res.file_path
        
        # Create Component
        component = Component(
            name=name,
            type=comp_type,
            bom_ref=name
        )
        
        # Add Hash (SHA256)
        if res.file_hash:
            component.hashes.add(HashType(
                alg=HashAlgorithm.SHA_256,
                content=res.file_hash
            ))
            
        # Add Properties (Status, Verification)
        # CycloneDX allows custom properties
        component.properties.add("veritensor:status", res.status)
        component.properties.add("veritensor:verified", str(res.identity_verified).lower())
        
        if res.threats:
            component.properties.add("veritensor:threats", "; ".join(res.threats))

        bom.components.add(component)

    # Serialize to JSON
    outputter = JsonV1Dot5(bom)
    return outputter.output_as_string()
