# Copyright 2025 Veritensor Security
# Logic adapted from AIsbom (Apache 2.0 License)
#
# This engine performs static analysis of Pickle bytecode.
# It emulates the Pickle VM stack to detect obfuscated calls (STACK_GLOBAL).


import pickletools
import io
import logging
from typing import List

logger = logging.getLogger(__name__)

# --- Security Policies (Allowlist) ---
SAFE_MODULES = {
    "torch", "numpy", "collections", "builtins", "copyreg", "typing",
    "datetime", "pathlib", "posixpath", "ntpath", "re", "copy",
    "functools", "operator", "warnings", "contextlib", "abc", "enum",
    "dataclasses", "types", "_operator", "complex", "_codecs",
    "pytorch_lightning", "sklearn", "pandas" # Added common ML libs
}

SAFE_BUILTINS = {
    "getattr", "setattr", "bytearray", "dict", "list", "set", "tuple",
    "slice", "frozenset", "range", "complex", "bool", "int", "float", 
    "str", "bytes", "object", "print" # print is sometimes used for debugging
}

DANGEROUS_GLOBALS = {
    "os": {"system", "popen", "execl", "execvp", "spawn"},
    "subprocess": {"Popen", "call", "check_call", "check_output", "run"},
    "builtins": {"eval", "exec", "compile", "open", "__import__"},
    "posix": {"system", "popen"},
    "webbrowser": {"open"},
    "socket": {"socket", "connect"},
    "marshal": {"loads"},
    "pickle": {"loads", "load"},
}

def _is_safe_import(module: str, name: str) -> bool:
    if module in SAFE_MODULES:
        if module in ("builtins", "__builtin__"):
            return name in SAFE_BUILTINS
        return True
    if module.startswith("torch.") or module.startswith("numpy."):
        return True
    if module.startswith("pathlib.") or module.startswith("re.") or module.startswith("collections."):
        return True
    return False

def scan_pickle_stream(data: bytes, strict_mode: bool = True) -> List[str]:
    # FIX: Increased limit to prevent false positives on deep PyTorch models
    MAX_MEMO_SIZE = 2048 
    
    threats = []
    memo = [] 

    try:
        stream = io.BytesIO(data)
        for opcode, arg, pos in pickletools.genops(stream):
            if opcode.name in ("SHORT_BINUNICODE", "UNICODE", "BINUNICODE"):
                memo.append(arg)
                if len(memo) > MAX_MEMO_SIZE: 
                    memo.pop(0)
            
            # Reset memo on STOP to clear stack between multiple pickles in one file
            elif opcode.name == "STOP":
                memo.clear()

            elif opcode.name == "GLOBAL":
                module, name = None, None
                if isinstance(arg, str):
                    if "\n" in arg:
                        module, name = arg.split("\n", 1)
                    elif " " in arg:
                        module, name = arg.split(" ", 1)
                if module and name:
                    threat = _check_import(module, name, strict_mode)
                    if threat: threats.append(threat)

            elif opcode.name == "STACK_GLOBAL":
                if len(memo) >= 2:
                    name = memo[-1]
                    module = memo[-2]
                    if isinstance(module, str) and isinstance(name, str):
                        threat = _check_import(module, name, strict_mode)
                        if threat: threats.append(f"{threat} (via STACK_GLOBAL)")
                memo.clear() # Clear after usage to prevent confusion

    except Exception as e:
        # Don't crash on malformed files, just log
        pass

    return threats

def _check_import(module: str, name: str, strict_mode: bool) -> str:
    if module in DANGEROUS_GLOBALS:
        if "*" in DANGEROUS_GLOBALS[module] or name in DANGEROUS_GLOBALS[module]:
            return f"CRITICAL: {module}.{name}"
    if strict_mode:
        if not _is_safe_import(module, name):
            return f"UNSAFE_IMPORT: {module}.{name}"
    return ""
