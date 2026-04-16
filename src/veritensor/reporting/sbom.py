# Copyright 2026 Veritensor Security Apache 2.0
# Generates AI Bill of Materials (AI-BOM) in CycloneDX 1.5 format.
#
# Replaces: src/veritensor/reporting/sbom.py
#
# What changed vs previous version:
#   - _classify_component_type(): datasets, wheels, notebooks now get correct CycloneDX types
#   - repo_id stored as ExternalReference + property (supplier API changed between lib v3/v4)
#   - detected_license properly passed via LicenseExpression / License
#   - threats are now individual indexed properties (veritensor:threat:0, :1, ...) instead of one joined string
#   - Graceful fallback to plain JSON if cyclonedx-python-lib is unavailable

from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger(__name__)

try:
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model import HashAlgorithm, HashType, Property, ExternalReference, ExternalReferenceType, XsUri
    from cyclonedx.model.license import License, LicenseExpression
    from cyclonedx.output.json import JsonV1Dot5
    _CYCLONEDX_AVAILABLE = True
except ImportError:
    _CYCLONEDX_AVAILABLE = False
    logger.warning("cyclonedx-python-lib not installed. --sbom will fall back to plain JSON.")

from veritensor.core.types import ScanResult


# ---------------------------------------------------------------------------
# Extension → CycloneDX 1.5 component type
# CycloneDX 1.5 is the first spec version with official "machine-learning-model" type.
# ---------------------------------------------------------------------------

_MODEL_EXTENSIONS = frozenset({
    "pkl", "pickle",    # Pickle (RCE vector — highest risk)
    "pt", "pth",        # PyTorch
    "bin",              # Generic weights (BERT, GPT-2, etc.)
    "safetensors",      # SafeTensors serialisation
    "onnx",             # ONNX Runtime
    "gguf", "ggml",     # llama.cpp quantised models
    "h5", "keras",      # TensorFlow / Keras
    "joblib",           # scikit-learn
    "ckpt",             # Generic checkpoints
})

_DATA_EXTENSIONS = frozenset({
    "parquet", "arrow", # Columnar dataset formats
    "csv", "tsv",       # Tabular data
    "jsonl", "ndjson",  # Line-delimited JSON (fine-tuning sets)
    "faiss", "index",   # Vector store indices
    "db", "sqlite",     # Embedded DBs used as vector stores
})

_LIBRARY_EXTENSIONS = frozenset({"whl", "egg"})


def _classify_component_type(file_path: str) -> "ComponentType":
    """Returns the most accurate CycloneDX 1.5 ComponentType for a given file path."""
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    if ext in _MODEL_EXTENSIONS:
        return ComponentType.MACHINE_LEARNING_MODEL
    if ext in _DATA_EXTENSIONS:
        return ComponentType.DATA
    if ext in _LIBRARY_EXTENSIONS:
        return ComponentType.LIBRARY
    # Notebooks are "files" in CycloneDX 1.5 — no dedicated notebook type exists yet
    return ComponentType.FILE


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_sbom(results: List[ScanResult]) -> str:
    """
    Generates a CycloneDX 1.5-compliant AI-BOM JSON string from scan results.

    Falls back to a plain JSON representation if cyclonedx-python-lib is not
    installed, so --sbom never crashes the CLI.
    """
    if not _CYCLONEDX_AVAILABLE:
        return _plain_json_fallback(results)

    bom = Bom()

    for res in results:
        filename = res.file_path.split("/")[-1] if res.file_path else "unknown"
        comp_type = _classify_component_type(res.file_path)

        component = Component(name=filename, type=comp_type, bom_ref=res.file_path)

        # Cryptographic hash
        if res.file_hash:
            try:
                component.hashes.add(HashType(alg=HashAlgorithm.SHA_256, content=res.file_hash))
            except Exception as e:
                logger.debug(f"Could not add hash: {e}")

        # License — try SPDX expression first (e.g. "Apache-2.0"), fall back to free-form name
        if res.detected_license:
            try:
                component.licenses.add(LicenseExpression(value=res.detected_license))
            except Exception:
                try:
                    component.licenses.add(License(name=res.detected_license))
                except Exception as e:
                    logger.debug(f"Could not add license: {e}")

        # HuggingFace repo — stored as ExternalReference + property.
        # We avoid the supplier field because its constructor API differs between lib v3 and v4.
        if res.repo_id:
            try:
                component.external_references.add(ExternalReference(
                    reference_type=ExternalReferenceType.DOCUMENTATION,
                    url=XsUri(f"https://huggingface.co/{res.repo_id}"),
                    comment="HuggingFace model card"
                ))
            except Exception as e:
                logger.debug(f"Could not add external reference: {e}")

        # Properties (Veritensor-specific metadata)
        _add_property(component, "veritensor:status", res.status)
        _add_property(component, "veritensor:identity_verified", str(res.identity_verified).lower())
        if res.repo_id:
            _add_property(component, "veritensor:source_repo", res.repo_id)

        # Each threat gets its own indexed property so consumers can iterate cleanly
        for i, threat in enumerate(res.threats or []):
            _add_property(component, f"veritensor:threat:{i}", threat[:512])

        bom.components.add(component)

    try:
        return JsonV1Dot5(bom).output_as_string()
    except Exception as e:
        logger.warning(f"CycloneDX serialisation failed ({e}), using plain JSON fallback.")
        return _plain_json_fallback(results)


def _add_property(component: "Component", name: str, value: str) -> None:
    """Adds a Property to a component, silently swallowing API shape differences."""
    try:
        component.properties.add(Property(name=name, value=value))
    except Exception as e:
        logger.debug(f"Property '{name}' skipped: {e}")


def _plain_json_fallback(results: List[ScanResult]) -> str:
    """Minimal CycloneDX-shaped JSON when the library is unavailable."""
    import json, uuid
    from datetime import datetime, timezone

    components = []
    for res in results:
        ext = res.file_path.rsplit(".", 1)[-1].lower() if "." in res.file_path else ""
        if ext in _MODEL_EXTENSIONS:     comp_type = "machine-learning-model"
        elif ext in _DATA_EXTENSIONS:    comp_type = "data"
        elif ext in _LIBRARY_EXTENSIONS: comp_type = "library"
        else:                            comp_type = "file"

        props = [
            {"name": "veritensor:status", "value": res.status},
            {"name": "veritensor:identity_verified", "value": str(res.identity_verified).lower()},
        ]
        if res.repo_id:
            props.append({"name": "veritensor:source_repo", "value": res.repo_id})
        for i, t in enumerate(res.threats or []):
            props.append({"name": f"veritensor:threat:{i}", "value": t[:512]})

        comp: dict = {"type": comp_type, "bom-ref": res.file_path,
                      "name": res.file_path.split("/")[-1], "properties": props}
        if res.file_hash:
            comp["hashes"] = [{"alg": "SHA-256", "content": res.file_hash}]
        if res.detected_license:
            comp["licenses"] = [{"license": {"name": res.detected_license}}]
        components.append(comp)

    return json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Veritensor Security", "name": "veritensor"}],
        },
        "components": components,
    }, indent=2, ensure_ascii=False)
