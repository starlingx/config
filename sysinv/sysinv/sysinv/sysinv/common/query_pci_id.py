#!/usr/bin/python
#
# Copyright (c) 2018-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from typing import List

from elftools.elf.elffile import ELFFile

_pmd_libraries_cache = None


def discover_pmd_libraries(
    base_dir: str = "/usr/lib/x86_64-linux-gnu/dpdk",
) -> List[str]:
    """Return a list of full paths to static PMD libraries under *base_dir*.
    Only regular, non-symlinked shared objects whose names start with
    ``librte_`` **and** contain ``.so.`` are considered.
    """
    global _pmd_libraries_cache

    if _pmd_libraries_cache is not None:
        return _pmd_libraries_cache

    libraries: List[str] = []

    if not os.path.exists(base_dir):
        _pmd_libraries_cache = libraries
        return libraries

    for subdir in os.listdir(base_dir):
        if not subdir.startswith("pmds-"):
            continue

        pmds_path = os.path.join(base_dir, subdir)
        if not os.path.isdir(pmds_path):
            continue

        for lib in os.listdir(pmds_path):
            if lib.startswith("librte_") and ".so." in lib:
                lib_path = os.path.join(pmds_path, lib)
                if os.path.isfile(lib_path) and not os.path.islink(lib_path):
                    libraries.append(lib_path)

    _pmd_libraries_cache = libraries
    return libraries


def extract_pmd_info_from_elf(filepath: str) -> List[dict]:
    """Extract PMD info directly from ELF file without subprocess"""
    pmd_infos = []

    try:
        with open(filepath, "rb") as f:
            elffile = ELFFile(f)

            section = elffile.get_section_by_name(".rodata")
            if section is None:
                section = elffile.get_section_by_name(b".rodata")

            if section is None:
                return pmd_infos

            data = section.data()
            dataptr = 0

            while dataptr < len(data):
                while dataptr < len(data) and not 32 <= data[dataptr] <= 127:
                    dataptr += 1

                if dataptr >= len(data):
                    break

                endptr = dataptr
                while endptr < len(data) and data[endptr] != 0:
                    endptr += 1

                mystring = data[dataptr:endptr].decode("utf-8", errors="ignore")
                rc = mystring.find("PMD_INFO_STRING")
                if rc != -1:
                    try:
                        i = mystring.index("=", rc)
                        json_str = mystring[i + 2:]
                        pmd_info = json.loads(json_str)
                        pmd_infos.append(pmd_info)
                    except (ValueError, json.JSONDecodeError):
                        pass

                dataptr = endptr

    except Exception:
        return extract_pmd_info_subprocess(filepath)

    return pmd_infos


def extract_pmd_info_subprocess(filepath: str) -> List[dict]:
    """Fallback to subprocess method"""
    pmd_infos = []
    cmd = ["python", "/usr/bin/dpdk-pmdinfo.py", "-r", filepath]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if line.strip():
                try:
                    pmd_info = json.loads(line)
                    pmd_infos.append(pmd_info)
                except json.JSONDecodeError:
                    continue
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return pmd_infos


def check_device_support(pmd_info: dict, vid: str, did: str) -> bool:
    """Check if a PMD info supports the given vendor/device ID"""
    try:
        supported_devices = pmd_info.get("pci_ids", [])
        for supported_device in supported_devices:
            if hex(supported_device[0]) == vid and hex(supported_device[1]) == did:
                return True
    except (KeyError, IndexError, TypeError):
        pass
    return False


def process_target(target: str, vid: str, did: str) -> bool:
    """Process a single target file for device support"""
    pmd_infos = extract_pmd_info_from_elf(target)

    for pmd_info in pmd_infos:
        if check_device_support(pmd_info, vid, did):
            return True
    return False


def call_query_pci_id(vid, did, pmdinfo=None, elf=None):
    """Call the query_pci_id utility to get extra info about a PCI device
    based on its vendor and device ids.
    """
    pmdinfo = pmdinfo if pmdinfo else "/usr/bin/dpdk-pmdinfo.py"
    elf = elf if elf else "/usr/sbin/ovs-vswitchd"
    if process_target(elf, vid, did):
        msg = f"Vendor ID: {vid} Device ID: {did} is supported"
        return True, msg

    main_pmd_infos = extract_pmd_info_from_elf(elf)

    if not main_pmd_infos:
        pmd_libraries = discover_pmd_libraries()

        if len(pmd_libraries) > 5:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(process_target, lib, vid, did): lib
                    for lib in pmd_libraries
                }

                for future in as_completed(futures):
                    if future.result():
                        msg = f"Vendor ID: {vid} Device ID: {did} is supported"
                        return True, msg
        else:
            for lib in pmd_libraries:
                if process_target(lib, vid, did):
                    msg = f"Vendor ID: {vid} Device ID: {did} is supported"
                    return True, msg

    msg = f"Vendor ID: {vid} Device ID: {did} is not supported"
    return False, msg
