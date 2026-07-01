#!/usr/bin/env python3
"""Patch the Neo Windows Steam build of Super Hexagon for higher FPS rendering.

The patch keeps the fixed update loop at the original 60 FPS, paces rendering at
higher FPS values, and interpolates selected visual state during draw calls. It
modifies only the user's local executable and does not redistribute game files.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import re
import shutil
import subprocess
import struct
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


APP_ID = "221640"
GAME_DIR_NAME = "Super Hexagon"
EXE_NAME = "SuperHexagon.exe"

ORIGINAL_REFRESH_HZ = 60
MIN_PATCH_REFRESH_HZ = ORIGINAL_REFRESH_HZ + 1

SUPPORTED_EXE_SHA256 = (
    "72b0c26053c37edd3435def461e9027cd6ffad12032db2fd0b32c256fdbee6b9"
)
SUPPORTED_EXE_SIZE = 1_467_904
SUPPORTED_IMAGE_BASE = 0x400000

PATCH_SECTION_NAME = b".shfps\x00"
PATCH_SECTION_SIZE = 0x400
PATCH_SECTION_CHARACTERISTICS = 0xE0000020  # code, execute, read, write
IMAGE_SCN_MEM_WRITE = 0x80000000
DIAGNOSTIC_SECTION_CHARACTERISTICS = PATCH_SECTION_CHARACTERISTICS

IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_BASE_RELOCATION_DIRECTORY_OFFSET = 5 * 8

# Legacy v1 patch constants. That patch changed the simulation divisor and
# accelerated tick-based gameplay timers. This version can detect and remove it
# before applying the corrected patch.
LEGACY_CALL_OFFSET = 0x31A53
LEGACY_CALL_VA = 0x432653
LEGACY_CAVE_OFFSET = 0x31AD3
LEGACY_CAVE_VA = 0x4326D3
LEGACY_DIV_ROUTINE_VA = 0x4EBC30
LEGACY_CAVE_SIZE = 13
LEGACY_ORIGINAL_CALL_BYTES = bytes.fromhex("e8 d8 95 0b 00")
LEGACY_ORIGINAL_CAVE_BYTES = b"\xcc" * LEGACY_CAVE_SIZE
LEGACY_CAVE_PREFIX = bytes.fromhex("c7 44 24 0c")

# Legacy high-tick experiment constants. That patch tried to run the whole game
# at 120/240 ticks and patched one known 60-tick threshold, but gameplay still
# ran too fast. Keep the signatures so users can migrate away from it.
TICK_THRESHOLD_OFFSET = 0x285E4
TICK_THRESHOLD_VA = 0x4291E4
TICK_THRESHOLD_FALLTHROUGH_VA = 0x4291EB
TICK_THRESHOLD_TARGET_VA = 0x429205

DRAW_HOOK_OFFSET = 0x30050
DRAW_HOOK_VA = 0x430C50
DRAW_TICKS_VA = 0x4387B0
DRAW_BODY_VA = 0x42FE40
TIMER_POINTER_VA = 0x55ED28
DOUBLE_ONE_VA = 0x4F16D0
FLOAT_ONE_VA = 0x4F1668
DOUBLE_FIVE_VA = 0x4F16F0
TIMER_POINTER_RVA = TIMER_POINTER_VA - SUPPORTED_IMAGE_BASE
DOUBLE_ONE_RVA = DOUBLE_ONE_VA - SUPPORTED_IMAGE_BASE
FLOAT_ONE_RVA = FLOAT_ONE_VA - SUPPORTED_IMAGE_BASE
DOUBLE_FIVE_RVA = DOUBLE_FIVE_VA - SUPPORTED_IMAGE_BASE
DRAW_HOOK_ORIGINAL_BYTES = bytes.fromhex(
    "56 8b f1 e8 58 7b 00 00 89 86 b8 0c 04 00 8b ce "
    "c7 86 bc 0c 04 00 00 00 00 00 5e e9 d0 f1 ff ff"
)
UPDATE_HOOK_OFFSET = 0x30400
UPDATE_HOOK_VA = 0x431000
UPDATE_HOOK_RETURN_VA = 0x43100A
UPDATE_HOOK_ORIGINAL_BYTES = bytes.fromhex("55 8b ec 83 ec 08 56 57 8b f1")
SWAP_HOOK_OFFSET = 0x4CFC0
SWAP_HOOK_VA = 0x44DBC0
SWAP_HOOK_RETURN_VA = 0x44DBC8
SWAP_HOOK_ORIGINAL_BYTES = bytes.fromhex("55 8b ec 8b 45 08 85 c0")

DIAGNOSTIC_COUNTER_LABELS = (
    "diag_update_counter",
    "diag_draw_counter",
    "diag_swap_counter",
)
PATCH_DATA_FLOATS = {
    "float_neg_180": -180.0,
    "float_180": 180.0,
    "float_360": 360.0,
}


class PatchError(RuntimeError):
    """Raised when an executable cannot be patched safely."""


@dataclass(frozen=True)
class Section:
    index: int
    name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    def name_text(self) -> str:
        return self.name.split(b"\x00", 1)[0].decode("ascii", errors="replace")


@dataclass(frozen=True)
class PEInfo:
    pe_offset: int
    optional_header_offset: int
    section_table_offset: int
    number_of_sections: int
    image_base: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    sections: tuple[Section, ...]


@dataclass(frozen=True)
class PatchSite:
    name: str
    offset: int
    virtual_address: int
    original: bytes
    replacement: bytes


@dataclass(frozen=True)
class ImageState:
    status: str
    sha256: str
    size: int
    supported_signatures: bool
    refresh_hz: int | None = None
    reason: str | None = None


@dataclass(frozen=True)
class DiagnosticResult:
    duration_seconds: float
    update_count: int
    draw_count: int
    swap_count: int


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_u16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def write_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def checked_rel32(source_va: int, target_va: int, instruction_length: int = 5) -> bytes:
    rel = target_va - (source_va + instruction_length)
    if not -(2**31) <= rel <= 2**31 - 1:
        raise PatchError(f"relative jump out of range: {source_va:#x} -> {target_va:#x}")
    return struct.pack("<i", rel)


def jmp(source_va: int, target_va: int) -> bytes:
    return b"\xe9" + checked_rel32(source_va, target_va)


def call(source_va: int, target_va: int) -> bytes:
    return b"\xe8" + checked_rel32(source_va, target_va)


def jne(source_va: int, target_va: int) -> bytes:
    return b"\x0f\x85" + checked_rel32(source_va, target_va, instruction_length=6)


def je(source_va: int, target_va: int) -> bytes:
    return b"\x0f\x84" + checked_rel32(source_va, target_va, instruction_length=6)


def jump_patch(source_va: int, target_va: int, length: int) -> bytes:
    if length < 5:
        raise PatchError("jump patch length must be at least 5 bytes")
    return jmp(source_va, target_va) + (b"\x90" * (length - 5))


def append_image_base_to_eax(code: bytearray, start_va: int) -> None:
    code += bytes.fromhex("e8 00 00 00 00")  # call next
    next_va = start_va + len(code)
    code += bytes.fromhex("58")  # pop eax
    code += bytes.fromhex("2d") + struct.pack("<I", next_va - SUPPORTED_IMAGE_BASE)


def append_increment_counter(code: bytearray, start_va: int, counter_va: int) -> None:
    append_image_base_to_eax(code, start_va)
    code += bytes.fromhex("ff 80") + struct.pack("<I", counter_va - SUPPORTED_IMAGE_BASE)


def slice_at(data: bytes | bytearray, offset: int, size: int) -> bytes:
    if len(data) < offset + size:
        return b""
    return bytes(data[offset : offset + size])


def parse_pe(data: bytes | bytearray) -> PEInfo:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PatchError("not a PE executable")

    pe_offset = read_u32(data, 0x3C)
    if len(data) < pe_offset + 0x18 or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise PatchError("invalid PE header")

    number_of_sections = read_u16(data, pe_offset + 6)
    optional_header_size = read_u16(data, pe_offset + 20)
    optional_header_offset = pe_offset + 24
    if read_u16(data, optional_header_offset) != 0x10B:
        raise PatchError("only PE32 executables are supported")

    image_base = read_u32(data, optional_header_offset + 28)
    section_alignment = read_u32(data, optional_header_offset + 32)
    file_alignment = read_u32(data, optional_header_offset + 36)
    size_of_image = read_u32(data, optional_header_offset + 56)
    size_of_headers = read_u32(data, optional_header_offset + 60)
    section_table_offset = optional_header_offset + optional_header_size

    sections: list[Section] = []
    for index in range(number_of_sections):
        offset = section_table_offset + index * 40
        if len(data) < offset + 40:
            raise PatchError("truncated section table")
        sections.append(
            Section(
                index=index,
                name=bytes(data[offset : offset + 8]),
                virtual_size=read_u32(data, offset + 8),
                virtual_address=read_u32(data, offset + 12),
                raw_size=read_u32(data, offset + 16),
                raw_pointer=read_u32(data, offset + 20),
                characteristics=read_u32(data, offset + 36),
            )
        )

    return PEInfo(
        pe_offset=pe_offset,
        optional_header_offset=optional_header_offset,
        section_table_offset=section_table_offset,
        number_of_sections=number_of_sections,
        image_base=image_base,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        sections=tuple(sections),
    )


def section_va(info: PEInfo, section: Section) -> int:
    return info.image_base + section.virtual_address


def patch_section(info: PEInfo) -> Section | None:
    for section in info.sections:
        if section.name.split(b"\x00", 1)[0] == PATCH_SECTION_NAME.rstrip(b"\x00"):
            return section
    return None


def section_header_offset(info: PEInfo, index: int) -> int:
    return info.section_table_offset + index * 40


def legacy_call_to_cave_bytes() -> bytes:
    return b"\xe8" + checked_rel32(LEGACY_CALL_VA, LEGACY_CAVE_VA)


def legacy_cave_fps(data: bytes | bytearray) -> int | None:
    cave = slice_at(data, LEGACY_CAVE_OFFSET, LEGACY_CAVE_SIZE)
    if len(cave) != LEGACY_CAVE_SIZE:
        return None
    if not cave.startswith(LEGACY_CAVE_PREFIX) or cave[8] != 0xE9:
        return None
    expected_jmp = checked_rel32(LEGACY_CAVE_VA + 8, LEGACY_DIV_ROUTINE_VA)
    if cave[9:13] != expected_jmp:
        return None
    return struct.unpack("<I", cave[4:8])[0]


def is_legacy_speed_patch(data: bytes | bytearray) -> bool:
    return (
        slice_at(data, LEGACY_CALL_OFFSET, len(LEGACY_ORIGINAL_CALL_BYTES))
        == legacy_call_to_cave_bytes()
        and legacy_cave_fps(data) is not None
    )


def restore_legacy_speed_patch(data: bytes | bytearray) -> bytes:
    restored = bytearray(data)
    restored[LEGACY_CALL_OFFSET : LEGACY_CALL_OFFSET + len(LEGACY_ORIGINAL_CALL_BYTES)] = (
        LEGACY_ORIGINAL_CALL_BYTES
    )
    restored[LEGACY_CAVE_OFFSET : LEGACY_CAVE_OFFSET + LEGACY_CAVE_SIZE] = (
        LEGACY_ORIGINAL_CAVE_BYTES
    )
    return bytes(restored)


def validate_refresh_hz(refresh_hz: int) -> None:
    if not is_supported_refresh_hz(refresh_hz):
        raise PatchError(
            f"FPS must be {ORIGINAL_REFRESH_HZ} to restore or a whole number "
            f"greater than {ORIGINAL_REFRESH_HZ}"
        )


def is_supported_refresh_hz(refresh_hz: int | None) -> bool:
    if refresh_hz is None:
        return False
    return refresh_hz == ORIGINAL_REFRESH_HZ or refresh_hz >= MIN_PATCH_REFRESH_HZ


def make_init_hook(start_va: int) -> bytes:
    code = bytearray()
    code += bytes.fromhex("80 3b 00")  # cmp byte ptr [ebx], 0
    code += bytes.fromhex("89 83 a0 00 00 00")  # mov [ebx+0xa0], eax
    code += bytes.fromhex("89 93 a4 00 00 00")  # mov [ebx+0xa4], edx
    code += bytes.fromhex("c7 83 d0 04 00 00 00 00 00 00")  # render_acc low = 0
    code += bytes.fromhex("c7 83 d4 04 00 00 00 00 00 00")  # render_acc high = 0
    code += jmp(start_va + len(code), 0x439943)
    return bytes(code)


def make_swap_accumulator_clamp(start_va: int, swap_observed_va: int) -> bytes:
    flag_rva = swap_observed_va - SUPPORTED_IMAGE_BASE
    code = bytearray()

    def patch_short_jump(offset: int, target_offset: int) -> None:
        rel = target_offset - (offset + 2)
        if not -128 <= rel <= 127:
            raise PatchError("internal swap pacing short jump out of range")
        code[offset + 1] = rel & 0xFF

    append_image_base_to_eax(code, start_va)
    code += bytes.fromhex("80 b8") + struct.pack("<I", flag_rva) + b"\x00"
    no_swap_jump = len(code)
    code += bytes.fromhex("74 00")  # je done
    code += bytes.fromhex("c6 80") + struct.pack("<I", flag_rva) + b"\x00"
    code += bytes.fromhex("83 bb d4 04 00 00 00")  # cmp render_acc high, 0
    high_ready_jump = len(code)
    code += bytes.fromhex("75 00")  # jne set ready
    code += bytes.fromhex("8b 83 d0 04 00 00")  # mov eax, render_acc low
    code += bytes.fromhex("3b 83 b8 00 00 00")  # cmp eax, render_interval low
    low_done_jump = len(code)
    code += bytes.fromhex("76 00")  # jbe done
    set_ready_offset = len(code)
    patch_short_jump(high_ready_jump, set_ready_offset)
    code += bytes.fromhex("8b 83 b8 00 00 00")  # mov eax, render_interval low
    code += bytes.fromhex("89 83 d0 04 00 00")  # render_acc low = interval low
    code += bytes.fromhex("33 c0")  # xor eax, eax
    code += bytes.fromhex("89 83 d4 04 00 00")  # render_acc high = 0
    done_offset = len(code)
    patch_short_jump(no_swap_jump, done_offset)
    patch_short_jump(low_done_jump, done_offset)
    code += bytes.fromhex("c3")  # ret
    return bytes(code)


def make_delta1_hook(start_va: int, swap_accumulator_clamp_va: int | None = None) -> bytes:
    code = bytearray()
    code += bytes.fromhex("01 b3 d0 04 00 00")  # add [render_acc], esi
    code += bytes.fromhex("11 8b d4 04 00 00")  # adc [render_acc+4], ecx
    if swap_accumulator_clamp_va is not None:
        code += call(start_va + len(code), swap_accumulator_clamp_va)
    code += bytes.fromhex("01 b3 a8 00 00 00")  # original add sim accumulator
    code += bytes.fromhex("8b b3 a8 00 00 00")  # original mov esi, sim_acc low
    code += bytes.fromhex("11 8b ac 00 00 00")  # original adc sim accumulator high
    code += bytes.fromhex("8b b3 d0 04 00 00")  # wait uses render_acc low
    code += bytes.fromhex("8b 8b d4 04 00 00")  # wait uses render_acc high
    code += jmp(start_va + len(code), 0x43997D)
    return bytes(code)


def make_delta2_hook(start_va: int, swap_accumulator_clamp_va: int | None = None) -> bytes:
    code = bytearray()
    code += bytes.fromhex("01 b3 d0 04 00 00")  # add [render_acc], esi
    code += bytes.fromhex("11 bb d4 04 00 00")  # adc [render_acc+4], edi
    if swap_accumulator_clamp_va is not None:
        code += call(start_va + len(code), swap_accumulator_clamp_va)
    code += bytes.fromhex("01 b3 a8 00 00 00")  # original add sim accumulator
    code += bytes.fromhex("8b 83 b8 00 00 00")  # original mov eax, [ebx+0xb8]
    code += bytes.fromhex("11 bb ac 00 00 00")  # original adc sim accumulator high
    code += jmp(start_va + len(code), 0x4399F0)
    return bytes(code)


def make_delta3_hook(start_va: int, swap_accumulator_clamp_va: int | None = None) -> bytes:
    code = bytearray()
    code += bytes.fromhex("01 b3 d0 04 00 00")  # add [render_acc], esi
    code += bytes.fromhex("11 8b d4 04 00 00")  # adc [render_acc+4], ecx
    if swap_accumulator_clamp_va is not None:
        code += call(start_va + len(code), swap_accumulator_clamp_va)
    code += bytes.fromhex("01 b3 a8 00 00 00")  # original add sim accumulator
    code += bytes.fromhex("89 93 a4 00 00 00")  # original mov [ebx+0xa4], edx
    code += bytes.fromhex("11 8b ac 00 00 00")  # original adc sim accumulator high
    code += jmp(start_va + len(code), 0x439B85)
    return bytes(code)


def make_render_end_hook(start_va: int) -> bytes:
    code = bytearray()
    code += bytes.fromhex("80 3b 00")  # cmp byte ptr [ebx], 0
    exit_jump_va = start_va + len(code)
    code += b"\x0f\x84\x00\x00\x00\x00"  # je exit
    code += bytes.fromhex("8b 83 b8 00 00 00")  # mov eax, [render_interval low]
    code += bytes.fromhex("8b 93 bc 00 00 00")  # mov edx, [render_interval high]
    code += bytes.fromhex("29 83 d0 04 00 00")  # sub [render_acc], eax
    code += bytes.fromhex("19 93 d4 04 00 00")  # sbb [render_acc+4], edx
    code += jmp(start_va + len(code), 0x439950)
    exit_va = start_va + len(code)
    struct.pack_into("<i", code, exit_jump_va - start_va + 2, exit_va - (exit_jump_va + 6))
    code += bytes.fromhex("c7 83 d0 04 00 00 00 00 00 00")
    code += bytes.fromhex("c7 83 d4 04 00 00 00 00 00 00")
    code += jmp(start_va + len(code), 0x439CF7)
    return bytes(code)


def make_draw_hook(
    start_va: int,
    draw_counter_va: int | None = None,
    include_wall_angle_interpolation: bool = True,
    previous_rotation_offset_va: int | None = None,
    float_neg_180_va: int | None = None,
    float_180_va: int | None = None,
    float_360_va: int | None = None,
) -> bytes:
    code = bytearray()
    include_rotation_offset_interpolation = previous_rotation_offset_va is not None
    if include_rotation_offset_interpolation and (
        float_neg_180_va is None or float_180_va is None or float_360_va is None
    ):
        raise PatchError("rotation offset interpolation requires angle constants")

    def patch_short_jump(offset: int, target_offset: int) -> None:
        rel = target_offset - (offset + 2)
        if not -128 <= rel <= 127:
            raise PatchError("internal draw hook short jump out of range")
        code[offset + 1] = rel & 0xFF

    if draw_counter_va is not None:
        append_increment_counter(code, start_va, draw_counter_va)

    code += bytes.fromhex("56")  # push esi
    code += bytes.fromhex("55")  # push ebp
    code += bytes.fromhex("8b f1")  # mov esi, ecx
    code += call(start_va + len(code), DRAW_TICKS_VA)
    code += bytes.fromhex("89 86 b8 0c 04 00")  # mov [esi+0x40cb8], eax
    code += bytes.fromhex("8b ce")  # mov ecx, esi
    code += bytes.fromhex("c7 86 bc 0c 04 00 00 00 00 00")  # draw flag = 0

    code += bytes.fromhex("83 ec 18")  # locals: saved fields + accumulator double
    code += bytes.fromhex("8b 86 24 29 00 00")  # mov eax, [esi+0x2924]
    code += bytes.fromhex("89 04 24")  # save original phase bits
    if include_wall_angle_interpolation:
        code += bytes.fromhex("8b 86 b8 29 00 00")  # mov eax, [esi+0x29b8]
        code += bytes.fromhex("89 44 24 08")  # save original wall angle offset bits
    if include_rotation_offset_interpolation:
        code += bytes.fromhex("8b 86 a0 01 00 00")  # mov eax, [esi+0x1a0]
        code += bytes.fromhex("89 44 24 0c")  # save original rotation offset bits

    code += bytes.fromhex("e8 00 00 00 00")  # call next
    next_va = start_va + len(code)
    code += bytes.fromhex("5d")  # pop ebp
    code += bytes.fromhex("81 ed") + struct.pack("<I", next_va - SUPPORTED_IMAGE_BASE)
    code += bytes.fromhex("8b 85") + struct.pack("<I", TIMER_POINTER_RVA)
    code += bytes.fromhex("85 c0")  # test eax, eax
    skip_jump_offset = len(code)
    code += bytes.fromhex("0f 84 00 00 00 00")  # je skip interpolation
    code += bytes.fromhex("8b 88 a8 00 00 00")  # sim accumulator low
    code += bytes.fromhex("8b 90 ac 00 00 00")  # sim accumulator high
    code += call(start_va + len(code), 0x4EB7A0)
    code += bytes.fromhex("f2 0f 11 44 24 10")  # save accumulator as double

    code += bytes.fromhex("8b 85") + struct.pack("<I", TIMER_POINTER_RVA)
    code += bytes.fromhex("8b 88 98 00 00 00")  # sim interval low
    code += bytes.fromhex("8b 90 9c 00 00 00")  # sim interval high
    code += bytes.fromhex("0b ca")  # or ecx, edx
    skip_zero_interval_offset = len(code)
    code += bytes.fromhex("0f 84 00 00 00 00")  # je skip interpolation
    code += call(start_va + len(code), 0x4EB7A0)

    code += bytes.fromhex("f2 0f 10 4c 24 10")  # xmm1 = accumulator
    code += bytes.fromhex("f2 0f 5e c8")  # xmm1 /= sim interval
    code += bytes.fromhex("f2 0f 5d 8d") + struct.pack("<I", DOUBLE_ONE_RVA)
    code += bytes.fromhex("f2 0f 59 8e 50 29 00 00")  # *= normalized delta
    code += bytes.fromhex("f2 0f 11 4c 24 10")  # save fractional tick for obstacles
    code += bytes.fromhex("66 0f 5a c9")  # double to float
    code += bytes.fromhex("f3 0f 10 86 24 29 00 00")  # current phase
    code += bytes.fromhex("f3 0f 58 c1")  # add interpolated fraction
    code += bytes.fromhex("f3 0f 11 86 24 29 00 00")  # temporary phase

    if include_wall_angle_interpolation:
        code += bytes.fromhex("f3 0f 10 8e b8 29 00 00")  # current wall angle offset
        code += bytes.fromhex("0f 57 d2")  # zero
        code += bytes.fromhex("0f 2f ca")
        skip_wall_angle_offset = len(code)
        code += bytes.fromhex("76 00")  # jbe skip wall angle interpolation
        code += bytes.fromhex("f2 0f 10 44 24 10")  # fractional tick
        code += bytes.fromhex("f2 0f 59 86 50 29 00 00")  # *= normalized delta
        code += bytes.fromhex("66 0f 5a c0")  # double to float
        code += bytes.fromhex("f3 0f 5c c8")  # temporary angle -= fraction
        code += bytes.fromhex("0f 2f ca")
        store_wall_angle_offset = len(code)
        code += bytes.fromhex("77 00")  # ja store positive value
        code += bytes.fromhex("0f 28 ca")  # clamp to zero
        store_wall_angle_va_offset = len(code)
        patch_short_jump(store_wall_angle_offset, store_wall_angle_va_offset)
        code += bytes.fromhex("f3 0f 11 8e b8 29 00 00")
        skip_wall_angle_va_offset = len(code)
        patch_short_jump(skip_wall_angle_offset, skip_wall_angle_va_offset)

    if include_rotation_offset_interpolation:
        code += bytes.fromhex("f3 0f 10 86 a0 01 00 00")  # current rotation offset
        code += bytes.fromhex("0f 28 c8")  # delta = current
        code += bytes.fromhex("f3 0f 5c 8d") + struct.pack(
            "<I", previous_rotation_offset_va - SUPPORTED_IMAGE_BASE
        )
        code += bytes.fromhex("0f 2f 8d") + struct.pack(
            "<I", float_180_va - SUPPORTED_IMAGE_BASE
        )
        skip_delta_high = len(code)
        code += bytes.fromhex("76 00")  # jbe skip high wrap correction
        code += bytes.fromhex("f3 0f 5c 8d") + struct.pack(
            "<I", float_360_va - SUPPORTED_IMAGE_BASE
        )
        patch_short_jump(skip_delta_high, len(code))
        code += bytes.fromhex("0f 2f 8d") + struct.pack(
            "<I", float_neg_180_va - SUPPORTED_IMAGE_BASE
        )
        skip_delta_low = len(code)
        code += bytes.fromhex("73 00")  # jae skip low wrap correction
        code += bytes.fromhex("f3 0f 58 8d") + struct.pack(
            "<I", float_360_va - SUPPORTED_IMAGE_BASE
        )
        patch_short_jump(skip_delta_low, len(code))
        code += bytes.fromhex("f2 0f 10 44 24 10")  # fractional tick
        code += bytes.fromhex("66 0f 5a c0")  # double to float
        code += bytes.fromhex("f3 0f 59 c8")  # delta *= fraction
        code += bytes.fromhex("f3 0f 10 86 a0 01 00 00")  # current rotation offset
        code += bytes.fromhex("f3 0f 58 c1")  # current += interpolated delta
        code += bytes.fromhex("0f 2f 85") + struct.pack(
            "<I", float_360_va - SUPPORTED_IMAGE_BASE
        )
        skip_result_high = len(code)
        code += bytes.fromhex("72 00")  # jb skip result high wrap
        code += bytes.fromhex("f3 0f 5c 85") + struct.pack(
            "<I", float_360_va - SUPPORTED_IMAGE_BASE
        )
        patch_short_jump(skip_result_high, len(code))
        code += bytes.fromhex("0f 57 d2")  # zero
        code += bytes.fromhex("0f 2f c2")  # compare result with zero
        skip_result_low = len(code)
        code += bytes.fromhex("73 00")  # jae skip result low wrap
        code += bytes.fromhex("f3 0f 58 85") + struct.pack(
            "<I", float_360_va - SUPPORTED_IMAGE_BASE
        )
        patch_short_jump(skip_result_low, len(code))
        code += bytes.fromhex("f3 0f 11 86 a0 01 00 00")  # temporary rotation offset

    code += bytes.fromhex("f3 0f 10 96 70 29 00 00")  # current acceleration ramp
    code += bytes.fromhex("0f 2f 95") + struct.pack("<I", FLOAT_ONE_RVA)
    high_speed_offset = len(code)
    code += bytes.fromhex("77 00")  # ja high speed branch
    code += bytes.fromhex("f2 0f 10 44 24 10")  # fractional tick
    code += bytes.fromhex("f2 0f 59 85") + struct.pack("<I", DOUBLE_FIVE_RVA)
    code += bytes.fromhex("0f 5a d2")  # ramp to double
    code += bytes.fromhex("f2 0f 59 c2")  # delta = fraction * 5.0 * ramp
    convert_delta_jump = len(code)
    code += bytes.fromhex("eb 00")
    high_speed_va_offset = len(code)
    patch_short_jump(high_speed_offset, high_speed_va_offset)
    code += bytes.fromhex("f3 0f 10 96 b0 54 00 00")  # stop timer
    code += bytes.fromhex("0f 57 c0")
    code += bytes.fromhex("0f 2f d0")
    no_obstacle_delta_offset = len(code)
    code += bytes.fromhex("77 00")  # ja no movement while stop timer is active
    code += bytes.fromhex("f2 0f 10 44 24 10")  # fractional tick
    code += bytes.fromhex("f3 0f 10 96 68 29 00 00")  # obstacle speed
    code += bytes.fromhex("0f 5a d2")  # speed to double
    code += bytes.fromhex("f2 0f 59 c2")  # delta = fraction * speed
    convert_delta_offset = len(code)
    patch_short_jump(convert_delta_jump, convert_delta_offset)
    code += bytes.fromhex("f2 0f 2c c0")  # integer pixels
    store_delta_jump = len(code)
    code += bytes.fromhex("eb 00")
    no_obstacle_delta_va_offset = len(code)
    patch_short_jump(no_obstacle_delta_offset, no_obstacle_delta_va_offset)
    code += bytes.fromhex("33 c0")
    store_delta_offset = len(code)
    patch_short_jump(store_delta_jump, store_delta_offset)
    code += bytes.fromhex("89 44 24 04")
    code += bytes.fromhex("85 c0")
    skip_obstacles_delta = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("8b 8e 20 29 00 00")  # active segment count
    code += bytes.fromhex("85 c9")
    skip_obstacles_count = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("8d 96 14 02 00 00")  # first segment
    obstacle_loop = len(code)
    code += bytes.fromhex("29 02")
    code += bytes.fromhex("29 42 04")
    code += bytes.fromhex("83 c2 14")
    code += bytes.fromhex("49")
    code += b"\x75" + struct.pack("b", obstacle_loop - (len(code) + 2))
    obstacle_skip = len(code)
    patch_short_jump(skip_obstacles_delta, obstacle_skip)
    patch_short_jump(skip_obstacles_count, obstacle_skip)

    skip_va = start_va + len(code)
    struct.pack_into("<i", code, skip_jump_offset + 2, skip_va - (start_va + skip_jump_offset + 6))
    struct.pack_into(
        "<i",
        code,
        skip_zero_interval_offset + 2,
        skip_va - (start_va + skip_zero_interval_offset + 6),
    )

    code += bytes.fromhex("8b ce")  # mov ecx, esi
    code += call(start_va + len(code), DRAW_BODY_VA)
    code += bytes.fromhex("8b 44 24 04")
    code += bytes.fromhex("85 c0")
    skip_restore_delta = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("8b 8e 20 29 00 00")
    code += bytes.fromhex("85 c9")
    skip_restore_count = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("8d 96 14 02 00 00")
    restore_loop = len(code)
    code += bytes.fromhex("01 02")
    code += bytes.fromhex("01 42 04")
    code += bytes.fromhex("83 c2 14")
    code += bytes.fromhex("49")
    code += b"\x75" + struct.pack("b", restore_loop - (len(code) + 2))
    restore_skip = len(code)
    patch_short_jump(skip_restore_delta, restore_skip)
    patch_short_jump(skip_restore_count, restore_skip)
    if include_wall_angle_interpolation:
        code += bytes.fromhex("8b 44 24 08")  # restore original wall angle offset bits
        code += bytes.fromhex("89 86 b8 29 00 00")
    if include_rotation_offset_interpolation:
        code += bytes.fromhex("8b 44 24 0c")  # restore original rotation offset bits
        code += bytes.fromhex("89 86 a0 01 00 00")
    code += bytes.fromhex("8b 04 24")  # restore original phase bits
    code += bytes.fromhex("89 86 24 29 00 00")
    code += bytes.fromhex("83 c4 18")
    code += bytes.fromhex("5d")
    code += bytes.fromhex("5e")
    code += bytes.fromhex("c3")
    return bytes(code)


def make_update_hook(
    start_va: int,
    previous_rotation_offset_va: int | None = None,
    update_counter_va: int | None = None,
) -> bytes:
    code = bytearray()
    if update_counter_va is not None or previous_rotation_offset_va is not None:
        code += bytes.fromhex("50")  # push eax
        code += bytes.fromhex("52")  # push edx
        if update_counter_va is not None:
            append_increment_counter(code, start_va, update_counter_va)
        if previous_rotation_offset_va is not None:
            append_image_base_to_eax(code, start_va)
            code += bytes.fromhex("8b 91 a0 01 00 00")  # mov edx, [ecx+0x1a0]
            code += bytes.fromhex("89 90") + struct.pack(
                "<I", previous_rotation_offset_va - SUPPORTED_IMAGE_BASE
            )
        code += bytes.fromhex("5a")  # pop edx
        code += bytes.fromhex("58")  # pop eax
    code += UPDATE_HOOK_ORIGINAL_BYTES
    code += jmp(start_va + len(code), UPDATE_HOOK_RETURN_VA)
    return bytes(code)


def make_swap_hook(
    start_va: int,
    swap_observed_va: int | None = None,
    swap_counter_va: int | None = None,
) -> bytes:
    code = bytearray()
    if swap_observed_va is not None or swap_counter_va is not None:
        append_image_base_to_eax(code, start_va)
        if swap_counter_va is not None:
            code += bytes.fromhex("ff 80") + struct.pack(
                "<I", swap_counter_va - SUPPORTED_IMAGE_BASE
            )
        if swap_observed_va is not None:
            code += bytes.fromhex("c6 80") + struct.pack(
                "<I", swap_observed_va - SUPPORTED_IMAGE_BASE
            ) + b"\x01"
    code += SWAP_HOOK_ORIGINAL_BYTES
    code += jmp(start_va + len(code), SWAP_HOOK_RETURN_VA)
    return bytes(code)


def make_sim_divisor_hook(start_va: int, refresh_hz: int) -> bytes:
    code = bytearray()
    code += bytes.fromhex("c7 44 24 0c") + struct.pack("<I", refresh_hz)
    code += jmp(start_va + len(code), LEGACY_DIV_ROUTINE_VA)
    return bytes(code)


def make_tick_threshold_hook(start_va: int, refresh_hz: int) -> bytes:
    code = bytearray()
    code += bytes.fromhex("81 be c8 0c 04 00") + struct.pack("<I", refresh_hz)
    code += je(start_va + len(code), TICK_THRESHOLD_TARGET_VA)
    code += jmp(start_va + len(code), TICK_THRESHOLD_FALLTHROUGH_VA)
    return bytes(code)


def build_patch_section(
    section_virtual_address: int,
    refresh_hz: int,
    include_draw_hook: bool = True,
    include_update_hook: bool = True,
    include_high_tick_legacy_hooks: bool = False,
    include_diagnostics: bool = False,
    include_swap_pacing: bool = True,
    include_wall_angle_interpolation: bool = True,
    include_rotation_offset_interpolation: bool = True,
) -> tuple[bytes, dict[str, int]]:
    builders = [
        ("init", make_init_hook),
        ("delta1", make_delta1_hook),
        ("delta2", make_delta2_hook),
        ("delta3", make_delta3_hook),
        ("render_end", make_render_end_hook),
    ]
    if include_draw_hook:
        builders.append(("draw", make_draw_hook))
    hz_builders = [
        ("sim_divisor", make_sim_divisor_hook),
        ("tick_threshold", make_tick_threshold_hook),
    ]
    payload = bytearray()
    labels: dict[str, int] = {}

    if include_rotation_offset_interpolation:
        labels["previous_rotation_offset"] = section_virtual_address + len(payload)
        payload += b"\x00" * 4
        for name, value in PATCH_DATA_FLOATS.items():
            labels[name] = section_virtual_address + len(payload)
            payload += struct.pack("<f", value)

    if include_swap_pacing:
        labels["swap_observed"] = section_virtual_address + len(payload)
        payload += b"\x00"
        while len(payload) % 4:
            payload += b"\x00"

    if include_diagnostics:
        for name in DIAGNOSTIC_COUNTER_LABELS:
            labels[name] = section_virtual_address + len(payload)
            payload += b"\x00" * 4
        while len(payload) % 4:
            payload += b"\x90"

    if include_swap_pacing:
        start_va = section_virtual_address + len(payload)
        labels["swap_accumulator_clamp"] = start_va
        payload += make_swap_accumulator_clamp(start_va, labels["swap_observed"])
        while len(payload) % 4:
            payload += b"\x90"

    for name, builder in builders:
        start_va = section_virtual_address + len(payload)
        labels[name] = start_va
        if name == "draw" and include_diagnostics:
            payload += builder(
                start_va,
                labels["diag_draw_counter"],
                include_wall_angle_interpolation=include_wall_angle_interpolation,
                previous_rotation_offset_va=labels.get("previous_rotation_offset"),
                float_neg_180_va=labels.get("float_neg_180"),
                float_180_va=labels.get("float_180"),
                float_360_va=labels.get("float_360"),
            )
        elif name == "draw":
            payload += builder(
                start_va,
                include_wall_angle_interpolation=include_wall_angle_interpolation,
                previous_rotation_offset_va=labels.get("previous_rotation_offset"),
                float_neg_180_va=labels.get("float_neg_180"),
                float_180_va=labels.get("float_180"),
                float_360_va=labels.get("float_360"),
            )
        else:
            if name.startswith("delta"):
                payload += builder(start_va, labels.get("swap_accumulator_clamp"))
            else:
                payload += builder(start_va)
        while len(payload) % 4:
            payload += b"\x90"

    if include_update_hook:
        start_va = section_virtual_address + len(payload)
        labels["update"] = start_va
        payload += make_update_hook(
            start_va,
            previous_rotation_offset_va=labels.get("previous_rotation_offset"),
            update_counter_va=labels.get("diag_update_counter") if include_diagnostics else None,
        )
        while len(payload) % 4:
            payload += b"\x90"

    if include_swap_pacing:
        start_va = section_virtual_address + len(payload)
        labels["swap"] = start_va
        payload += make_swap_hook(
            start_va,
            swap_observed_va=labels["swap_observed"],
            swap_counter_va=labels.get("diag_swap_counter") if include_diagnostics else None,
        )
        if include_high_tick_legacy_hooks:
            while len(payload) % 4:
                payload += b"\x90"
    elif include_diagnostics:
        start_va = section_virtual_address + len(payload)
        labels["swap_diagnostic"] = start_va
        payload += make_swap_hook(start_va, swap_counter_va=labels["diag_swap_counter"])
        while len(payload) % 4:
            payload += b"\x90"

    if include_high_tick_legacy_hooks:
        for name, builder in hz_builders:
            start_va = section_virtual_address + len(payload)
            labels[name] = start_va
            payload += builder(start_va, refresh_hz)
            while len(payload) % 4:
                payload += b"\x90"

    if len(payload) > PATCH_SECTION_SIZE:
        raise PatchError("internal patch payload does not fit in patch section")
    payload += b"\x00" * (PATCH_SECTION_SIZE - len(payload))
    return bytes(payload), labels


def original_patch_sites(
    include_draw_hook: bool = True,
    include_update_hook: bool = True,
    include_high_tick_legacy_sites: bool = False,
    include_diagnostics: bool = False,
    include_swap_pacing: bool = True,
) -> list[PatchSite]:
    sites = [
        PatchSite(
            "render divisor",
            0x319DF,
            0x4325DF,
            bytes.fromhex("68 fa 00 00 00"),
            bytes.fromhex("68 fa 00 00 00"),
        ),
        PatchSite(
            "init hook",
            0x38D34,
            0x439934,
            bytes.fromhex("80 3b 00 89 83 a0 00 00 00 89 93 a4 00 00 00"),
            b"",
        ),
        PatchSite(
            "delta hook 1",
            0x38D6B,
            0x43996B,
            bytes.fromhex("01 b3 a8 00 00 00 8b b3 a8 00 00 00 11 8b ac 00 00 00"),
            b"",
        ),
        PatchSite(
            "wait high 1",
            0x38D8F,
            0x43998F,
            bytes.fromhex("8b 83 9c 00 00 00"),
            bytes.fromhex("8b 83 bc 00 00 00"),
        ),
        PatchSite(
            "wait low 1",
            0x38D9B,
            0x43999B,
            bytes.fromhex("8b 93 98 00 00 00"),
            bytes.fromhex("8b 93 b8 00 00 00"),
        ),
        PatchSite(
            "delta hook 2",
            0x38DDE,
            0x4399DE,
            bytes.fromhex("01 b3 a8 00 00 00 8b 83 b8 00 00 00 11 bb ac 00 00 00"),
            b"",
        ),
        PatchSite(
            "wait low after sleep",
            0x38F00,
            0x439B00,
            bytes.fromhex("8b bb a8 00 00 00"),
            bytes.fromhex("8b bb d0 04 00 00"),
        ),
        PatchSite(
            "wait high after sleep",
            0x38F0E,
            0x439B0E,
            bytes.fromhex("8b b3 ac 00 00 00"),
            bytes.fromhex("8b b3 d4 04 00 00"),
        ),
        PatchSite(
            "wait low 2",
            0x38F1C,
            0x439B1C,
            bytes.fromhex("8b 93 98 00 00 00"),
            bytes.fromhex("8b 93 b8 00 00 00"),
        ),
        PatchSite(
            "wait high compare 2",
            0x38F22,
            0x439B22,
            bytes.fromhex("3b 83 9c 00 00 00"),
            bytes.fromhex("3b 83 bc 00 00 00"),
        ),
        PatchSite(
            "wait high exact",
            0x38F38,
            0x439B38,
            bytes.fromhex("8b 83 9c 00 00 00"),
            bytes.fromhex("8b 83 bc 00 00 00"),
        ),
        PatchSite(
            "wait exact low",
            0x38F40,
            0x439B40,
            bytes.fromhex("8b bb a8 00 00 00"),
            bytes.fromhex("8b bb d0 04 00 00"),
        ),
        PatchSite(
            "wait exact high",
            0x38F46,
            0x439B46,
            bytes.fromhex("8b b3 ac 00 00 00"),
            bytes.fromhex("8b b3 d4 04 00 00"),
        ),
        PatchSite(
            "delta hook 3",
            0x38F73,
            0x439B73,
            bytes.fromhex("01 b3 a8 00 00 00 89 93 a4 00 00 00 11 8b ac 00 00 00"),
            b"",
        ),
        PatchSite(
            "busy wait high",
            0x38F85,
            0x439B85,
            bytes.fromhex("8b 83 ac 00 00 00"),
            bytes.fromhex("8b 83 d4 04 00 00"),
        ),
        PatchSite(
            "busy wait low",
            0x38F8B,
            0x439B8B,
            bytes.fromhex("8b 8b a8 00 00 00"),
            bytes.fromhex("8b 8b d0 04 00 00"),
        ),
        PatchSite(
            "busy wait high compare",
            0x38F91,
            0x439B91,
            bytes.fromhex("3b 83 9c 00 00 00"),
            bytes.fromhex("3b 83 bc 00 00 00"),
        ),
        PatchSite(
            "busy wait low compare",
            0x38F9B,
            0x439B9B,
            bytes.fromhex("3b 8b 98 00 00 00"),
            bytes.fromhex("3b 8b b8 00 00 00"),
        ),
        PatchSite(
            "render end hook",
            0x390EE,
            0x439CEE,
            bytes.fromhex("80 3b 00 0f 85 59 fc ff ff"),
            b"",
        ),
    ]
    if include_draw_hook:
        sites.append(
            PatchSite(
                "draw hook",
                DRAW_HOOK_OFFSET,
                DRAW_HOOK_VA,
                DRAW_HOOK_ORIGINAL_BYTES,
                b"",
            )
        )
    if include_update_hook:
        sites.append(
            PatchSite(
                "update hook",
                UPDATE_HOOK_OFFSET,
                UPDATE_HOOK_VA,
                UPDATE_HOOK_ORIGINAL_BYTES,
                b"",
            )
        )
    if include_high_tick_legacy_sites:
        sites.extend(
            [
                PatchSite(
                    "simulation divisor call",
                    LEGACY_CALL_OFFSET,
                    LEGACY_CALL_VA,
                    LEGACY_ORIGINAL_CALL_BYTES,
                    b"",
                ),
                PatchSite(
                    "tick threshold",
                    TICK_THRESHOLD_OFFSET,
                    TICK_THRESHOLD_VA,
                    bytes.fromhex("83 be c8 0c 04 00 3c"),
                    b"",
                ),
            ]
        )
    if include_swap_pacing:
        sites.append(
            PatchSite(
                "swap hook",
                SWAP_HOOK_OFFSET,
                SWAP_HOOK_VA,
                SWAP_HOOK_ORIGINAL_BYTES,
                b"",
            )
        )
    elif include_diagnostics:
        sites.extend(
            [
                PatchSite(
                    "swap diagnostic hook",
                    SWAP_HOOK_OFFSET,
                    SWAP_HOOK_VA,
                    SWAP_HOOK_ORIGINAL_BYTES,
                    b"",
                ),
            ]
        )
    return sites


def patched_sites(
    section_virtual_address: int,
    labels: dict[str, int],
    refresh_hz: int,
    include_draw_hook: bool = True,
    include_update_hook: bool = True,
    include_high_tick_legacy_sites: bool = False,
    include_diagnostics: bool = False,
    include_swap_pacing: bool = True,
) -> list[PatchSite]:
    sites: list[PatchSite] = []
    for site in original_patch_sites(
        include_draw_hook=include_draw_hook,
        include_update_hook=include_update_hook,
        include_high_tick_legacy_sites=include_high_tick_legacy_sites,
        include_diagnostics=include_diagnostics,
        include_swap_pacing=include_swap_pacing,
    ):
        replacement = site.replacement
        if site.name == "render divisor":
            replacement = b"\x68" + struct.pack("<I", refresh_hz)
        elif site.name == "init hook":
            replacement = jump_patch(site.virtual_address, labels["init"], len(site.original))
        elif site.name == "delta hook 1":
            replacement = jump_patch(site.virtual_address, labels["delta1"], len(site.original))
        elif site.name == "delta hook 2":
            replacement = jump_patch(site.virtual_address, labels["delta2"], len(site.original))
        elif site.name == "delta hook 3":
            replacement = jump_patch(site.virtual_address, labels["delta3"], len(site.original))
        elif site.name == "render end hook":
            replacement = jump_patch(site.virtual_address, labels["render_end"], len(site.original))
        elif site.name == "draw hook":
            replacement = jump_patch(site.virtual_address, labels["draw"], len(site.original))
        elif site.name == "update hook":
            replacement = jump_patch(site.virtual_address, labels["update"], len(site.original))
        elif site.name == "simulation divisor call":
            replacement = call(site.virtual_address, labels["sim_divisor"])
        elif site.name == "tick threshold":
            replacement = jump_patch(site.virtual_address, labels["tick_threshold"], len(site.original))
        elif site.name == "swap hook":
            replacement = jump_patch(site.virtual_address, labels["swap"], len(site.original))
        elif site.name == "swap diagnostic hook":
            replacement = jump_patch(site.virtual_address, labels["swap_diagnostic"], len(site.original))

        sites.append(
            PatchSite(
                name=site.name,
                offset=site.offset,
                virtual_address=site.virtual_address,
                original=site.original,
                replacement=replacement,
            )
        )
    return sites


def current_render_divisor(data: bytes | bytearray) -> int | None:
    raw = slice_at(data, 0x319DF, 5)
    if len(raw) != 5 or raw[0] != 0x68:
        return None
    return struct.unpack("<I", raw[1:5])[0]


def all_sites_match(data: bytes | bytearray, sites: Iterable[PatchSite], replacement: bool) -> bool:
    for site in sites:
        expected = site.replacement if replacement else site.original
        if slice_at(data, site.offset, len(expected)) != expected:
            return False
    return True


def has_legacy_draw_stack_layout(
    section_payload: bytes,
    labels: dict[str, int],
    section_virtual_address: int,
) -> bool:
    draw_va = labels.get("draw")
    if draw_va is None:
        return False
    draw_offset = draw_va - section_virtual_address
    draw_hook = section_payload[draw_offset : draw_offset + 0x240]
    return (
        bytes.fromhex("83 ec 10") in draw_hook
        and bytes.fromhex("f2 0f 11 44 24 08") in draw_hook
        and bytes.fromhex("83 c4 10") in draw_hook
    )


def install_or_update_patch_section(
    data: bytes,
    refresh_hz: int,
    include_diagnostics: bool = False,
) -> tuple[bytes, PEInfo, Section, dict[str, int]]:
    info = parse_pe(data)
    existing = patch_section(info)
    patched = bytearray(data)
    characteristics = (
        DIAGNOSTIC_SECTION_CHARACTERISTICS if include_diagnostics else PATCH_SECTION_CHARACTERISTICS
    )

    if existing is None:
        if info.section_table_offset + (info.number_of_sections + 1) * 40 > info.size_of_headers:
            raise PatchError("not enough PE header space to add patch section")

        last = max(
            info.sections,
            key=lambda section: section.virtual_address
            + align_up(max(section.virtual_size, section.raw_size), info.section_alignment),
        )
        raw_pointer = align_up(len(patched), info.file_alignment)
        virtual_address = align_up(
            last.virtual_address
            + align_up(max(last.virtual_size, last.raw_size), info.section_alignment),
            info.section_alignment,
        )
        raw_size = align_up(PATCH_SECTION_SIZE, info.file_alignment)

        if len(patched) < raw_pointer:
            patched += b"\x00" * (raw_pointer - len(patched))

        header_offset = section_header_offset(info, info.number_of_sections)
        patched[header_offset : header_offset + 8] = PATCH_SECTION_NAME.ljust(8, b"\x00")
        write_u32(patched, header_offset + 8, PATCH_SECTION_SIZE)
        write_u32(patched, header_offset + 12, virtual_address)
        write_u32(patched, header_offset + 16, raw_size)
        write_u32(patched, header_offset + 20, raw_pointer)
        write_u32(patched, header_offset + 24, 0)
        write_u32(patched, header_offset + 28, 0)
        write_u16(patched, header_offset + 32, 0)
        write_u16(patched, header_offset + 34, 0)
        write_u32(patched, header_offset + 36, characteristics)

        write_u16(patched, info.pe_offset + 6, info.number_of_sections + 1)
        write_u32(
            patched,
            info.optional_header_offset + 56,
            align_up(virtual_address + PATCH_SECTION_SIZE, info.section_alignment),
        )

        new_section_va = info.image_base + virtual_address
        payload, labels = build_patch_section(
            new_section_va,
            refresh_hz,
            include_diagnostics=include_diagnostics,
        )
        patched += payload
        patched += b"\x00" * (raw_size - len(payload))

        updated_info = parse_pe(patched)
        section = patch_section(updated_info)
        if section is None:
            raise PatchError("failed to add patch section")
        return bytes(patched), updated_info, section, labels

    section = existing
    if section.raw_size < PATCH_SECTION_SIZE:
        raise PatchError("existing patch section is too small")
    if len(patched) < section.raw_pointer + section.raw_size:
        raise PatchError("existing patch section points outside the file")

    header_offset = section_header_offset(info, section.index)
    write_u32(patched, header_offset + 8, PATCH_SECTION_SIZE)
    write_u32(patched, header_offset + 36, characteristics)

    payload, labels = build_patch_section(
        section_va(info, section),
        refresh_hz,
        include_diagnostics=include_diagnostics,
    )
    patched[section.raw_pointer : section.raw_pointer + len(payload)] = payload
    return bytes(patched), info, section, labels


def write_patch_sites(
    data: bytes,
    section: Section,
    info: PEInfo,
    refresh_hz: int,
    include_diagnostics: bool = False,
) -> bytes:
    payload, labels = build_patch_section(
        section_va(info, section),
        refresh_hz,
        include_diagnostics=include_diagnostics,
    )
    patched = bytearray(data)
    patched[section.raw_pointer : section.raw_pointer + len(payload)] = payload
    for site in patched_sites(
        section_va(info, section),
        labels,
        refresh_hz,
        include_diagnostics=include_diagnostics,
    ):
        current = slice_at(patched, site.offset, len(site.original))
        current_replacement = slice_at(patched, site.offset, len(site.replacement))
        if site.name == "render divisor":
            divisor = current_render_divisor(patched)
            if current != site.original and not is_supported_refresh_hz(divisor):
                raise PatchError(f"unexpected bytes at {site.name}")
        elif current not in {site.original, site.replacement} and current_replacement != site.replacement:
            raise PatchError(f"unexpected bytes at {site.name}")
        patched[site.offset : site.offset + len(site.replacement)] = site.replacement
    return bytes(patched)


def diagnostic_patch_sites_for_image(data: bytes | bytearray) -> list[PatchSite]:
    try:
        info = parse_pe(data)
    except PatchError:
        return []
    section = patch_section(info)
    divisor = current_render_divisor(data)
    if section is None or not is_supported_refresh_hz(divisor):
        return []
    _payload, labels = build_patch_section(
        section_va(info, section),
        divisor,
        include_diagnostics=True,
    )
    return [
        site
        for site in patched_sites(
            section_va(info, section),
            labels,
            divisor,
            include_diagnostics=True,
        )
        if site.name in {"update diagnostic hook", "swap diagnostic hook"}
    ]


def restore_original_sites(data: bytes) -> bytes:
    restored = bytearray(data)
    for site in original_patch_sites():
        restored[site.offset : site.offset + len(site.original)] = site.original
    for site in diagnostic_patch_sites_for_image(data):
        if slice_at(restored, site.offset, len(site.replacement)) == site.replacement:
            restored[site.offset : site.offset + len(site.original)] = site.original
    for site in original_patch_sites(
        include_draw_hook=False,
        include_high_tick_legacy_sites=True,
    ):
        restored[site.offset : site.offset + len(site.original)] = site.original
    if is_legacy_speed_patch(restored):
        restored = bytearray(restore_legacy_speed_patch(restored))
    return bytes(restored)


def restore_diagnostic_sites(data: bytes) -> bytes:
    restored = bytearray(data)
    restored[UPDATE_HOOK_OFFSET : UPDATE_HOOK_OFFSET + len(UPDATE_HOOK_ORIGINAL_BYTES)] = (
        UPDATE_HOOK_ORIGINAL_BYTES
    )
    restored[SWAP_HOOK_OFFSET : SWAP_HOOK_OFFSET + len(SWAP_HOOK_ORIGINAL_BYTES)] = (
        SWAP_HOOK_ORIGINAL_BYTES
    )
    return bytes(restored)


def restore_legacy_high_tick_patch(data: bytes, refresh_hz: int) -> bytes:
    info = parse_pe(data)
    section = patch_section(info)
    if section is None:
        return data
    _payload, labels = build_patch_section(
        section_va(info, section),
        refresh_hz,
        include_draw_hook=False,
        include_update_hook=False,
        include_high_tick_legacy_hooks=True,
        include_swap_pacing=False,
        include_rotation_offset_interpolation=False,
    )
    restored = bytearray(data)
    for site in patched_sites(
        section_va(info, section),
        labels,
        refresh_hz,
        include_draw_hook=False,
        include_update_hook=False,
        include_high_tick_legacy_sites=True,
        include_swap_pacing=False,
    ):
        restored[site.offset : site.offset + len(site.original)] = site.original
    return bytes(restored)


def remove_patch_section(data: bytes) -> bytes:
    info = parse_pe(data)
    section = patch_section(info)
    restored = bytearray(restore_original_sites(data))
    if section is None:
        return bytes(restored)

    if section.index != info.number_of_sections - 1:
        raise PatchError("patch section is not the last section; refusing to remove it")

    previous = info.sections[section.index - 1]
    header_offset = section_header_offset(info, section.index)
    restored[header_offset : header_offset + 40] = b"\x00" * 40
    write_u16(restored, info.pe_offset + 6, info.number_of_sections - 1)
    write_u32(
        restored,
        info.optional_header_offset + 56,
        align_up(
            previous.virtual_address
            + align_up(max(previous.virtual_size, previous.raw_size), info.section_alignment),
            info.section_alignment,
        ),
    )

    truncate_at = section.raw_pointer
    if len(restored) >= section.raw_pointer + section.raw_size:
        restored = restored[:truncate_at]
    return bytes(restored)


def analyze_image(data: bytes) -> ImageState:
    digest = sha256_bytes(data)
    known_hash = digest == SUPPORTED_EXE_SHA256 and len(data) == SUPPORTED_EXE_SIZE

    if is_legacy_speed_patch(data):
        return ImageState(
            "legacy-speedup",
            digest,
            len(data),
            supported_signatures=True,
            refresh_hz=legacy_cave_fps(data),
            reason="old patch changes the simulation step and accelerates gameplay",
        )

    try:
        info = parse_pe(data)
    except PatchError as exc:
        return ImageState("unsupported", digest, len(data), False, reason=str(exc))

    section = patch_section(info)
    if section is not None:
        divisor = current_render_divisor(data)
        if not is_supported_refresh_hz(divisor):
            return ImageState(
                "conflict",
                digest,
                len(data),
                False,
                refresh_hz=divisor,
                reason="patch section exists, but render divisor is not a supported refresh",
            )
        diagnostic_payload, diagnostic_labels = build_patch_section(
            section_va(info, section),
            divisor,
            include_diagnostics=True,
        )
        diagnostic_section_payload = slice_at(data, section.raw_pointer, len(diagnostic_payload))
        diagnostic_sites = patched_sites(
            section_va(info, section),
            diagnostic_labels,
            divisor,
            include_diagnostics=True,
        )
        if diagnostic_section_payload == diagnostic_payload and all_sites_match(
            data,
            diagnostic_sites,
            replacement=True,
        ):
            return ImageState("diagnostic", digest, len(data), True, refresh_hz=divisor)

        old_diagnostic_payload, old_diagnostic_labels = build_patch_section(
            section_va(info, section),
            divisor,
            include_diagnostics=True,
            include_swap_pacing=False,
        )
        old_diagnostic_section_payload = slice_at(
            data, section.raw_pointer, len(old_diagnostic_payload)
        )
        old_diagnostic_sites = patched_sites(
            section_va(info, section),
            old_diagnostic_labels,
            divisor,
            include_diagnostics=True,
            include_swap_pacing=False,
        )
        if old_diagnostic_section_payload == old_diagnostic_payload and all_sites_match(
            data,
            old_diagnostic_sites,
            replacement=True,
        ):
            return ImageState(
                "legacy-no-swap-pacing",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch lacks swap-aware render pacing",
            )

        payload, labels = build_patch_section(section_va(info, section), divisor)
        section_payload = slice_at(data, section.raw_pointer, len(payload))
        sites = patched_sites(section_va(info, section), labels, divisor)
        if section_payload == payload and all_sites_match(data, sites, replacement=True):
            return ImageState("patched", digest, len(data), True, refresh_hz=divisor)

        no_swap_payload, no_swap_labels = build_patch_section(
            section_va(info, section),
            divisor,
            include_swap_pacing=False,
        )
        no_swap_section_payload = slice_at(data, section.raw_pointer, len(no_swap_payload))
        no_swap_sites = patched_sites(
            section_va(info, section),
            no_swap_labels,
            divisor,
            include_swap_pacing=False,
        )
        if no_swap_section_payload == no_swap_payload and all_sites_match(
            data,
            no_swap_sites,
            replacement=True,
        ):
            return ImageState(
                "legacy-no-swap-pacing",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch lacks swap-aware render pacing",
            )

        no_rotation_payload, no_rotation_labels = build_patch_section(
            section_va(info, section),
            divisor,
            include_update_hook=False,
            include_swap_pacing=False,
            include_rotation_offset_interpolation=False,
        )
        no_rotation_sites = patched_sites(
            section_va(info, section),
            no_rotation_labels,
            divisor,
            include_update_hook=False,
            include_swap_pacing=False,
        )
        no_rotation_section_payload = slice_at(data, section.raw_pointer, len(no_rotation_payload))
        if no_rotation_section_payload == no_rotation_payload and all_sites_match(
            data,
            no_rotation_sites,
            replacement=True,
        ):
            return ImageState(
                "legacy-no-rotation-offset",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch leaves a core rotation offset at 60 FPS",
            )
        if all_sites_match(data, no_rotation_sites, replacement=True) and has_legacy_draw_stack_layout(
            no_rotation_section_payload,
            no_rotation_labels,
            section_va(info, section),
        ):
            return ImageState(
                "legacy-no-rotation-offset",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch leaves a core rotation offset at 60 FPS and has a stale draw stack layout",
            )

        no_wall_payload, no_wall_labels = build_patch_section(
            section_va(info, section),
            divisor,
            include_update_hook=False,
            include_swap_pacing=False,
            include_wall_angle_interpolation=False,
            include_rotation_offset_interpolation=False,
        )
        no_wall_sites = patched_sites(
            section_va(info, section),
            no_wall_labels,
            divisor,
            include_update_hook=False,
            include_swap_pacing=False,
        )
        no_wall_section_payload = slice_at(data, section.raw_pointer, len(no_wall_payload))
        if no_wall_section_payload == no_wall_payload and all_sites_match(
            data,
            no_wall_sites,
            replacement=True,
        ):
            return ImageState(
                "legacy-no-wall-angle",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch interpolates tick phase and obstacles but leaves wall angle at 60 FPS",
            )
        if all_sites_match(data, no_wall_sites, replacement=True) and has_legacy_draw_stack_layout(
            no_wall_section_payload,
            no_wall_labels,
            section_va(info, section),
        ):
            return ImageState(
                "legacy-no-wall-angle",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch interpolates tick phase and obstacles but leaves wall angle at 60 FPS",
            )

        old_payload, old_labels = build_patch_section(
            section_va(info, section),
            divisor,
            include_draw_hook=False,
            include_update_hook=False,
            include_swap_pacing=False,
            include_rotation_offset_interpolation=False,
        )
        old_sites = patched_sites(
            section_va(info, section),
            old_labels,
            divisor,
            include_draw_hook=False,
            include_update_hook=False,
            include_swap_pacing=False,
        )
        old_section_payload = slice_at(data, section.raw_pointer, len(old_payload))
        if old_section_payload == old_payload and all_sites_match(data, old_sites, replacement=True):
            return ImageState(
                "legacy-render-only",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch redraws at higher FPS but leaves game state at 60 FPS",
            )

        high_tick_payload, high_tick_labels = build_patch_section(
            section_va(info, section),
            divisor,
            include_draw_hook=False,
            include_update_hook=False,
            include_high_tick_legacy_hooks=True,
            include_swap_pacing=False,
            include_rotation_offset_interpolation=False,
        )
        high_tick_sites = patched_sites(
            section_va(info, section),
            high_tick_labels,
            divisor,
            include_draw_hook=False,
            include_update_hook=False,
            include_high_tick_legacy_sites=True,
            include_swap_pacing=False,
        )
        high_tick_section_payload = slice_at(data, section.raw_pointer, len(high_tick_payload))
        if high_tick_section_payload == high_tick_payload and all_sites_match(
            data,
            high_tick_sites,
            replacement=True,
        ):
            return ImageState(
                "legacy-high-tick",
                digest,
                len(data),
                True,
                refresh_hz=divisor,
                reason="old patch runs the simulation above 60 FPS and accelerates gameplay",
            )
        return ImageState(
            "conflict",
            digest,
            len(data),
            False,
            refresh_hz=divisor,
            reason="patch section or patch sites do not match this patcher",
        )

    original_sites_ok = all_sites_match(data, original_patch_sites(), replacement=False)
    if original_sites_ok:
        return ImageState("original", digest, len(data), known_hash, refresh_hz=ORIGINAL_REFRESH_HZ)

    return ImageState(
        "unsupported",
        digest,
        len(data),
        False,
        reason="expected original patch signatures were not found",
    )


def patch_image(
    data: bytes,
    refresh_hz: int,
    force: bool = False,
    diagnostics: bool = False,
) -> tuple[bytes, ImageState, bool]:
    validate_refresh_hz(refresh_hz)
    state = analyze_image(data)
    migrated_from_legacy = state.status == "legacy-speedup"
    target_status = "diagnostic" if diagnostics else "patched"

    if refresh_hz == ORIGINAL_REFRESH_HZ and not diagnostics:
        restored, restored_state, changed = unpatch_image(data)
        return restored, restored_state, changed

    if state.status == "legacy-speedup":
        data = restore_legacy_speed_patch(data)
        state = analyze_image(data)

    if state.status == "legacy-high-tick":
        data = restore_legacy_high_tick_patch(data, state.refresh_hz or refresh_hz)

    if state.status in {
        "patched",
        "diagnostic",
        "legacy-no-swap-pacing",
        "legacy-no-rotation-offset",
        "legacy-no-wall-angle",
        "legacy-render-only",
        "legacy-high-tick",
    }:
        if (
            (diagnostics and state.status != "diagnostic")
            or (
                not diagnostics
                and state.status
                in {
                    "diagnostic",
                    "legacy-no-swap-pacing",
                    "legacy-no-rotation-offset",
                    "legacy-no-wall-angle",
                    "legacy-render-only",
                    "legacy-high-tick",
                }
            )
        ):
            data = restore_original_sites(data)

        patched_info = parse_pe(data)
        section = patch_section(patched_info)
        if section is None:
            raise PatchError("patched state has no patch section")
        data, patched_info, section, _labels = install_or_update_patch_section(
            data,
            refresh_hz,
            include_diagnostics=diagnostics,
        )
        patched = write_patch_sites(
            data,
            section,
            patched_info,
            refresh_hz,
            include_diagnostics=diagnostics,
        )
        new_state = analyze_image(patched)
        if new_state.status != target_status:
            raise PatchError(new_state.reason or "failed to apply patch")
        return patched, new_state, new_state.sha256 != state.sha256

    if state.status != "original":
        raise PatchError(state.reason or f"cannot patch executable in state: {state.status}")

    if not state.supported_signatures and not force and not migrated_from_legacy:
        raise PatchError(
            "unsupported executable hash/signatures. Re-run with --force only if this is "
            "the Neo Windows Steam build and you accept patching by byte signatures."
        )

    with_section, info, section, _labels = install_or_update_patch_section(
        data,
        refresh_hz,
        include_diagnostics=diagnostics,
    )
    patched = write_patch_sites(
        with_section,
        section,
        info,
        refresh_hz,
        include_diagnostics=diagnostics,
    )
    new_state = analyze_image(patched)
    if new_state.status != target_status:
        raise PatchError(new_state.reason or "failed to apply patch")
    return patched, new_state, True


def unpatch_image(data: bytes) -> tuple[bytes, ImageState, bool]:
    state = analyze_image(data)
    if state.status == "original":
        return data, state, False

    if state.status == "legacy-speedup":
        restored = restore_legacy_speed_patch(data)
        return restored, analyze_image(restored), True

    if state.status not in {
        "patched",
        "diagnostic",
        "legacy-no-swap-pacing",
        "legacy-no-rotation-offset",
        "legacy-no-wall-angle",
        "legacy-render-only",
        "legacy-high-tick",
    }:
        raise PatchError(state.reason or f"cannot unpatch executable in state: {state.status}")

    restored = remove_patch_section(data)
    return restored, analyze_image(restored), True


def backup_path_for(exe_path: Path) -> Path:
    return exe_path.with_name(f"{exe_path.name}.bak")


def write_image(path: Path, data: bytes) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_bytes(data)
    os.replace(tmp_path, path)


def backup_is_valid_original(data: bytes, force: bool = False) -> bool:
    state = analyze_image(data)
    return state.status == "original" and (state.supported_signatures or force)


def original_image_for_backup(data: bytes, force: bool) -> bytes:
    state = analyze_image(data)
    if state.status == "original":
        if not state.supported_signatures and not force:
            raise PatchError(
                "refusing to back up unsupported original executable. Re-run with --force only "
                "if this is a layout-compatible Neo Windows Steam build."
            )
        return data

    restored, restored_state, _changed = unpatch_image(data)
    if restored_state.status != "original" or (not restored_state.supported_signatures and not force):
        raise PatchError("could not reconstruct a valid original executable for backup")
    return restored


def legacy_backup_paths(exe_path: Path) -> list[Path]:
    return sorted(exe_path.parent.glob(f"{exe_path.name}.bak.*"))


def ensure_backup_file(exe_path: Path, current_data: bytes, force: bool) -> None:
    backup_path = backup_path_for(exe_path)
    if backup_path.exists():
        backup_data = backup_path.read_bytes()
        if backup_is_valid_original(backup_data, force=force):
            print(f"Backup already exists: {backup_path}")
            return
        try:
            replacement_data = original_image_for_backup(current_data, force=force)
        except PatchError as exc:
            raise PatchError(
                f"backup exists but is not valid for this build: {backup_path}. "
                f"Could not replace it safely: {exc}"
            ) from exc
        write_image(backup_path, replacement_data)
        print(f"Backup replaced: {backup_path}")
        return

    for legacy_path in legacy_backup_paths(exe_path):
        try:
            legacy_data = legacy_path.read_bytes()
        except OSError:
            continue
        if backup_is_valid_original(legacy_data, force=force):
            shutil.copy2(legacy_path, backup_path)
            print(f"Backup migrated: {backup_path} (from {legacy_path.name})")
            return

    write_image(backup_path, original_image_for_backup(current_data, force=force))
    print(f"Backup written: {backup_path}")


def patch_file(exe_path: Path, refresh_hz: int, force: bool, backup: bool) -> ImageState:
    original = exe_path.read_bytes()
    if backup:
        ensure_backup_file(exe_path, original, force=force)
    patched, state, changed = patch_image(original, refresh_hz=refresh_hz, force=force)
    if changed:
        write_image(exe_path, patched)
    return state


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


def win_error(prefix: str) -> PatchError:
    error_code = ctypes.windll.kernel32.GetLastError()
    return PatchError(f"{prefix}: {ctypes.WinError(error_code)}")


def ensure_windows_diagnostics() -> None:
    if sys.platform != "win32":
        raise PatchError("runtime diagnostics are only supported on Windows")


def find_process_module_base(process_id: int, module_name: str) -> int:
    ensure_windows_diagnostics()
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        process_id,
    )
    if snapshot == wintypes.HANDLE(-1).value:
        raise win_error("CreateToolhelp32Snapshot failed")

    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            raise win_error("Module32FirstW failed")

        expected = module_name.lower()
        while True:
            if entry.szModule.lower() == expected:
                if entry.modBaseAddr is None:
                    raise PatchError(f"module base for {module_name} is null")
                return int(entry.modBaseAddr)
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    raise PatchError(f"could not find module {module_name} in process {process_id}")


def read_process_u32s(process_id: int, addresses: Iterable[int]) -> list[int]:
    ensure_windows_diagnostics()
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, process_id)
    if not handle:
        raise win_error("OpenProcess failed")

    try:
        values: list[int] = []
        for address in addresses:
            value = ctypes.c_uint32()
            bytes_read = ctypes.c_size_t()
            ok = kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(value),
                ctypes.sizeof(value),
                ctypes.byref(bytes_read),
            )
            if not ok or bytes_read.value != ctypes.sizeof(value):
                raise win_error(f"ReadProcessMemory failed at {address:#x}")
            values.append(value.value)
        return values
    finally:
        kernel32.CloseHandle(handle)


def diagnostic_counter_rvas(data: bytes, refresh_hz: int) -> dict[str, int]:
    info = parse_pe(data)
    section = patch_section(info)
    if section is None:
        raise PatchError("diagnostic image has no patch section")
    _payload, labels = build_patch_section(
        section_va(info, section),
        refresh_hz,
        include_diagnostics=True,
    )
    return {name: labels[name] - info.image_base for name in DIAGNOSTIC_COUNTER_LABELS}


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def diagnose_file(
    exe_path: Path,
    refresh_hz: int,
    duration_seconds: float,
    warmup_seconds: float,
    force: bool,
) -> DiagnosticResult:
    ensure_windows_diagnostics()
    original = exe_path.read_bytes()
    diagnostic_image, state, _changed = patch_image(
        original,
        refresh_hz=refresh_hz,
        force=force,
        diagnostics=True,
    )
    if state.status != "diagnostic":
        raise PatchError(state.reason or "failed to create diagnostic image")

    counter_rvas = diagnostic_counter_rvas(diagnostic_image, refresh_hz)
    write_image(exe_path, diagnostic_image)

    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen([str(exe_path)], cwd=str(exe_path.parent))
        warmup_deadline = time.perf_counter() + warmup_seconds
        while time.perf_counter() < warmup_deadline:
            if process.poll() is not None:
                raise PatchError(f"game exited during diagnostics with code {process.returncode}")
            time.sleep(0.1)

        if process.poll() is not None:
            raise PatchError(f"game exited during diagnostics with code {process.returncode}")

        module_base = find_process_module_base(process.pid, exe_path.name)
        addresses = [
            module_base + counter_rvas["diag_update_counter"],
            module_base + counter_rvas["diag_draw_counter"],
            module_base + counter_rvas["diag_swap_counter"],
        ]
        start_counts = read_process_u32s(process.pid, addresses)

        start = time.perf_counter()
        deadline = start + duration_seconds
        while time.perf_counter() < deadline:
            if process.poll() is not None:
                raise PatchError(f"game exited during diagnostics with code {process.returncode}")
            time.sleep(0.1)

        elapsed = time.perf_counter() - start
        if process.poll() is not None:
            raise PatchError(f"game exited during diagnostics with code {process.returncode}")

        end_counts = read_process_u32s(process.pid, addresses)
        update_count, draw_count, swap_count = [
            after - before for before, after in zip(start_counts, end_counts)
        ]
        return DiagnosticResult(
            duration_seconds=elapsed,
            update_count=update_count,
            draw_count=draw_count,
            swap_count=swap_count,
        )
    finally:
        if process is not None:
            terminate_process(process)
        write_image(exe_path, original)


def unpatch_file(exe_path: Path) -> ImageState:
    backup_path = backup_path_for(exe_path)
    if backup_path.exists():
        backup_data = backup_path.read_bytes()
        if backup_is_valid_original(backup_data):
            if exe_path.read_bytes() != backup_data:
                write_image(exe_path, backup_data)
            return analyze_image(backup_data)

        current_data = exe_path.read_bytes()
        try:
            restored_data = original_image_for_backup(current_data, force=False)
        except PatchError as exc:
            raise PatchError(
                f"backup exists but is not valid for this build: {backup_path}. "
                f"Could not restore without it: {exc}"
            ) from exc
        if current_data != restored_data:
            write_image(exe_path, restored_data)
        write_image(backup_path, restored_data)
        return analyze_image(restored_data)

    restored, state, changed = unpatch_image(exe_path.read_bytes())
    if changed:
        write_image(exe_path, restored)
    return state


def decode_vdf_path(value: str) -> str:
    return value.replace("\\\\", "\\")


def parse_steam_libraryfolders(text: str) -> list[Path]:
    paths: list[Path] = []
    for match in re.finditer(r'"path"\s+"([^"]+)"', text, flags=re.IGNORECASE):
        paths.append(Path(decode_vdf_path(match.group(1))))

    # Older Steam VDF format: "1" "D:\\SteamLibrary"
    for match in re.finditer(r'"\d+"\s+"([^"]+)"', text):
        value = match.group(1)
        if ":" in value or value.startswith("\\\\"):
            paths.append(Path(decode_vdf_path(value)))

    return unique_paths(paths)


def parse_manifest_installdir(text: str) -> str | None:
    match = re.search(r'"installdir"\s+"([^"]+)"', text, flags=re.IGNORECASE)
    if not match:
        return None
    return decode_vdf_path(match.group(1))


def registry_steam_roots() -> list[Path]:
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    roots: list[Path] = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Valve\Steam"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Valve\Steam"),
    ]
    values = ("SteamPath", "InstallPath")
    for hive, key_name in keys:
        try:
            with winreg.OpenKey(hive, key_name) as key:
                for value_name in values:
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                    except OSError:
                        continue
                    if value:
                        roots.append(Path(str(value)))
        except OSError:
            continue
    return unique_paths(roots)


def default_steam_roots() -> list[Path]:
    candidates: list[Path] = []
    for env_name in ("ProgramFiles(x86)", "ProgramFiles"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(Path(value) / "Steam")
    return unique_paths(candidates)


def steam_libraries() -> list[Path]:
    roots = unique_paths(registry_steam_roots() + default_steam_roots())
    libraries: list[Path] = []
    for root in roots:
        libraries.append(root)
        vdf_path = root / "steamapps" / "libraryfolders.vdf"
        if vdf_path.exists():
            try:
                libraries.extend(parse_steam_libraryfolders(vdf_path.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                pass
    return unique_paths(libraries)


def steam_exe_candidates() -> list[Path]:
    candidates: list[Path] = []
    for library in steam_libraries():
        steamapps = library / "steamapps"
        manifest = steamapps / f"appmanifest_{APP_ID}.acf"
        install_dirs = [GAME_DIR_NAME]
        if manifest.exists():
            try:
                install_dir = parse_manifest_installdir(
                    manifest.read_text(encoding="utf-8", errors="ignore")
                )
            except OSError:
                install_dir = None
            if install_dir:
                install_dirs.insert(0, install_dir)
        for install_dir in install_dirs:
            candidates.append(steamapps / "common" / install_dir / EXE_NAME)
    return unique_paths(candidates)


def local_exe_candidates() -> list[Path]:
    roots = unique_paths([Path.cwd(), Path(__file__).resolve().parent])
    candidates: list[Path] = []
    for root in roots:
        candidates.append(root / EXE_NAME)
        candidates.append(root / GAME_DIR_NAME / EXE_NAME)
    return unique_paths(candidates)


def unique_paths(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        normalized = str(path.expanduser()).lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(path.expanduser())
    return unique


def resolve_exe(path_arg: str | None) -> Path:
    if path_arg:
        path = Path(path_arg).expanduser()
        if path.is_dir():
            path = path / EXE_NAME
        if not path.exists():
            raise PatchError(f"executable not found: {path}")
        return path.resolve()

    candidates = [path for path in local_exe_candidates() + steam_exe_candidates() if path.exists()]
    if not candidates:
        raise PatchError(
            f"could not find {EXE_NAME}. Pass --path with the executable or game install folder."
        )
    return candidates[0].resolve()


def format_state(state: ImageState) -> str:
    lines = [
        f"State: {state.status}",
        f"SHA-256: {state.sha256}",
        f"Size: {state.size} bytes",
        f"Supported signatures: {'yes' if state.supported_signatures else 'no'}",
    ]
    if state.refresh_hz is not None:
        lines.append(f"Target FPS: {state.refresh_hz}")
    if state.reason:
        lines.append(f"Reason: {state.reason}")
    return "\n".join(lines)


def format_diagnostic_result(result: DiagnosticResult) -> str:
    duration = max(result.duration_seconds, 0.001)

    def line(name: str, count: int) -> str:
        return f"{name}: {count} ({count / duration:.1f}/s)"

    return "\n".join(
        [
            f"Measured duration: {result.duration_seconds:.2f}s",
            line("Update calls", result.update_count),
            line("Draw calls", result.draw_count),
            line("Swap calls", result.swap_count),
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Patch the Neo Windows Steam build for higher FPS rendering without speeding up gameplay."
    )
    parser.add_argument(
        "--path",
        help="Path to SuperHexagon.exe or to the Super Hexagon install folder.",
    )

    subparsers = parser.add_subparsers(dest="command")

    status = subparsers.add_parser("status", help="Show patch state.")
    status.add_argument(
        "--path",
        default=argparse.SUPPRESS,
        help="Path to SuperHexagon.exe or to the Super Hexagon install folder.",
    )
    status.set_defaults(command="status")

    patch = subparsers.add_parser("patch", help="Apply or update the FPS patch.")
    patch.add_argument(
        "--path",
        default=argparse.SUPPRESS,
        help="Path to SuperHexagon.exe or to the Super Hexagon install folder.",
    )
    patch.add_argument(
        "--fps",
        dest="refresh_hz",
        metavar="FPS",
        type=int,
        required=True,
        help=f"Target FPS. Use {ORIGINAL_REFRESH_HZ} to restore, or any whole number "
        f"greater than {ORIGINAL_REFRESH_HZ}.",
    )
    patch.add_argument(
        "--force",
        action="store_true",
        help="Patch by byte signature even when the executable hash is unknown.",
    )
    patch.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create, migrate, or refresh the stable .bak copy before patching.",
    )
    patch.set_defaults(command="patch")

    unpatch = subparsers.add_parser("unpatch", help="Restore the original executable layout.")
    unpatch.add_argument(
        "--path",
        default=argparse.SUPPRESS,
        help="Path to SuperHexagon.exe or to the Super Hexagon install folder.",
    )
    unpatch.set_defaults(command="unpatch")

    diagnose = subparsers.add_parser(
        "diagnose",
        help="Temporarily instrument update/draw/swap and measure real runtime rates.",
    )
    diagnose.add_argument(
        "--path",
        default=argparse.SUPPRESS,
        help="Path to SuperHexagon.exe or to the Super Hexagon install folder.",
    )
    diagnose.add_argument(
        "--fps",
        dest="refresh_hz",
        metavar="FPS",
        type=int,
        required=True,
        help=f"Diagnostic target FPS. Use {ORIGINAL_REFRESH_HZ} to restore, or any whole number "
        f"greater than {ORIGINAL_REFRESH_HZ}.",
    )
    diagnose.add_argument(
        "--seconds",
        type=float,
        default=5.0,
        help="How long to run the game while counting calls. Default: 5.",
    )
    diagnose.add_argument(
        "--warmup",
        type=float,
        default=2.0,
        help="Seconds to wait before measuring, so startup/loading is excluded. Default: 2.",
    )
    diagnose.add_argument(
        "--force",
        action="store_true",
        help="Patch by byte signature even when the executable hash is unknown.",
    )
    diagnose.set_defaults(command="diagnose")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "status"

    try:
        exe_path = resolve_exe(args.path)
        print(f"Executable: {exe_path}")

        if command == "status":
            state = analyze_image(exe_path.read_bytes())
            print(format_state(state))
            return (
                0
                if state.status
                in {
                    "original",
                    "patched",
                    "diagnostic",
                    "legacy-no-swap-pacing",
                    "legacy-no-rotation-offset",
                    "legacy-no-wall-angle",
                    "legacy-speedup",
                    "legacy-render-only",
                    "legacy-high-tick",
                }
                else 2
            )

        if command == "patch":
            state = patch_file(
                exe_path,
                refresh_hz=args.refresh_hz,
                force=args.force,
                backup=not args.no_backup,
            )
            print(format_state(state))
            if args.refresh_hz == ORIGINAL_REFRESH_HZ:
                print("Original 60 FPS behavior restored.")
            elif state.status == "patched":
                print("High FPS patch applied.")
            return 0

        if command == "unpatch":
            state = unpatch_file(exe_path)
            print(format_state(state))
            if state.status == "original":
                print("Patch removed.")
            return 0

        if command == "diagnose":
            if args.seconds <= 0:
                raise PatchError("--seconds must be greater than zero")
            if args.warmup < 0:
                raise PatchError("--warmup must not be negative")
            result = diagnose_file(
                exe_path,
                refresh_hz=args.refresh_hz,
                duration_seconds=args.seconds,
                warmup_seconds=args.warmup,
                force=args.force,
            )
            print(format_diagnostic_result(result))
            print("Executable restored to its pre-diagnostic bytes.")
            return 0

        parser.error(f"unknown command: {command}")
        return 2

    except PatchError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"File error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
