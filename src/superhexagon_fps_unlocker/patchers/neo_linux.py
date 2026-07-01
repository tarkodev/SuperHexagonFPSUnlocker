#!/usr/bin/env python3
"""Patch the Neo Linux Steam build of Super Hexagon for higher FPS rendering.

This patcher targets the non-stripped ELF64 build currently shipped on Steam.
It keeps simulation timing at the original 60 FPS cadence and raises render
pacing without mutating draw-time visual state.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import struct
from dataclasses import dataclass
from pathlib import Path


ORIGINAL_REFRESH_HZ = 60
DEFAULT_REFRESH_HZ = 240
MIN_PATCH_REFRESH_HZ = ORIGINAL_REFRESH_HZ + 1

SUPPORTED_EXE_SHA256 = (
    "6f13c58d136b84df212cc23a560f7383e2f689005af18072e51d8a7439d2ba1d"
)
SUPPORTED_EXE_SIZE = 2_253_968
DEFAULT_EXE_MODE = 0o755

PATCH_MAGIC = b"SHFPSLNX"
PATCH_VERSION = 2
LEGACY_TIMING_SCALE_PATCH_VERSION = 1

IMAGE_BASE = 0x400000
DATA_FILE_DELTA = 0x600000

SET_GAME_FRAME_RATE_VA = 0x47A990
SET_GAME_FRAME_RATE_OFFSET = SET_GAME_FRAME_RATE_VA - IMAGE_BASE
PATCH_REGION_SIZE = 0x380
UPDATE_HOOK_CAVE_REL = 0x60
OF_SET_FRAME_RATE_CAVE_REL = 0xC0
DRAW_HOOK_CAVE_REL = 0xF0
PATCH_DATA_REL = 0x300
PATCH_METADATA_REL = 0x360
LEGACY_UPDATE_HOOK_CAVE_REL = 0x80
LEGACY_OF_SET_FRAME_RATE_CAVE_REL = 0x120
LEGACY_PATCH_METADATA_REL = 0x340

UPDATE_HOOK_VA = 0x47A440
UPDATE_HOOK_OFFSET = UPDATE_HOOK_VA - IMAGE_BASE
UPDATE_HOOK_SIZE = 9
UPDATE_CONTINUE_VA = 0x47A449
OF_GET_LAST_FRAME_TIME_VA = 0x486430
OF_GET_ELAPSED_TIME_MILLIS_VA = 0x4863F0

DRAW_HOOK_VA = 0x47A540
DRAW_HOOK_OFFSET = DRAW_HOOK_VA - IMAGE_BASE
DRAW_HOOK_SIZE = 27
GAMERENDER_VA = 0x479190

OF_SET_FRAME_RATE_VA = 0x486440
OF_SET_FRAME_RATE_OFFSET = OF_SET_FRAME_RATE_VA - IMAGE_BASE
OF_SET_FRAME_RATE_SIZE = 30

CONSTRUCTOR_TIMER_VA = 0x485EC5
CONSTRUCTOR_TIMER_OFFSET = CONSTRUCTOR_TIMER_VA - IMAGE_BASE
CONSTRUCTOR_TIMER_SIZE = 54

EXPECTED_FRAME_DELTA_VA = 0x7F48A8
EXPECTED_FRAME_DELTA_OFFSET = EXPECTED_FRAME_DELTA_VA - DATA_FILE_DELTA
PATCH_MUTABLE_DATA_VA = 0x7F48B0
WINDOW_GLOBAL_VA = 0x7F5908

SUPERHEX_FPS_OFFSET = 0x3C720
SUPERHEX_FRAME_DELTA_OFFSET = 0x3C728
WINDOW_FREQ_OFFSET = 0x500
WINDOW_FRAME_INTERVAL_OFFSET = 0xD0

WALL_ANGLE_OFFSET = 0x28F8
ROTATION_OFFSET = 0x104
NORMALIZED_DELTA_OFFSET = 0x28C0
OBSTACLE_SPEED_OFFSET = 0x28D8
ACCELERATION_RAMP_OFFSET = 0x28E0
STOP_TIMER_OFFSET = 0x5420
ACTIVE_SEGMENT_COUNT_OFFSET = 0x2890
FIRST_SEGMENT_OFFSET = 0x180
SEGMENT_STRIDE = 0x14

ORIGINAL_UPDATE_PROLOGUE = bytes.fromhex("53 48 89 fb e8 e7 bf 00 00")
ORIGINAL_OF_SET_FRAME_RATE = bytes.fromhex(
    "48 8b 0d c1 f4 36 00 48 63 ff 31 d2 48 8b 81 00 05 00 00 "
    "48 f7 f7 48 89 81 d0 00 00 00 c3"
)
ORIGINAL_CONSTRUCTOR_TIMER = bytes.fromhex(
    "48 ba 89 88 88 88 88 88 88 88 48 89 f8 c7 83 f8 04 00 00 "
    "00 00 00 00 48 f7 e2 c6 83 38 05 00 00 00 c6 83 39 05 "
    "00 00 00 c6 03 01 48 c1 ea 05 48 89 93 d0 00 00 00"
)
ORIGINAL_EXPECTED_FRAME_DELTA = struct.pack("<f", 1.0)


class PatchError(RuntimeError):
    """Raised when an executable cannot be patched safely."""


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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slice_at(data: bytes | bytearray, offset: int, size: int) -> bytes:
    if len(data) < offset + size:
        return b""
    return bytes(data[offset : offset + size])


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


def rel32(source_va: int, target_va: int, instruction_length: int = 5) -> bytes:
    rel = target_va - (source_va + instruction_length)
    if not -(2**31) <= rel <= 2**31 - 1:
        raise PatchError(f"relative branch out of range: {source_va:#x} -> {target_va:#x}")
    return struct.pack("<i", rel)


def jmp(source_va: int, target_va: int) -> bytes:
    return b"\xe9" + rel32(source_va, target_va)


def call(source_va: int, target_va: int) -> bytes:
    return b"\xe8" + rel32(source_va, target_va)


def patch_near_jump(code: bytearray, start_va: int, jump_offset: int, target_offset: int) -> None:
    rel = (start_va + target_offset) - (start_va + jump_offset + 6)
    if not -(2**31) <= rel <= 2**31 - 1:
        raise PatchError("internal near jump out of range")
    struct.pack_into("<i", code, jump_offset + 2, rel)


def patch_short_jump(code: bytearray, jump_offset: int, target_offset: int) -> None:
    rel = target_offset - (jump_offset + 2)
    if not -128 <= rel <= 127:
        raise PatchError("internal short jump out of range")
    code[jump_offset + 1] = rel & 0xFF


def rip_disp(source_va: int, target_va: int, instruction_length: int) -> bytes:
    disp = target_va - (source_va + instruction_length)
    if not -(2**31) <= disp <= 2**31 - 1:
        raise PatchError(f"RIP-relative displacement out of range: {source_va:#x} -> {target_va:#x}")
    return struct.pack("<i", disp)


def jump_patch(source_va: int, target_va: int, length: int) -> bytes:
    if length < 5:
        raise PatchError("jump patch length must be at least 5 bytes")
    return jmp(source_va, target_va) + (b"\x90" * (length - 5))


def mov_superhex_fps_fields(register_opcode: int, refresh_hz: int) -> bytes:
    # c7 /0 disp32 imm32: mov dword ptr [rdi/rbx + disp], imm32
    modrm = bytes([register_opcode])
    return b"".join(
        [
            b"\xc7" + modrm + struct.pack("<I", SUPERHEX_FPS_OFFSET) + struct.pack("<I", refresh_hz),
            b"\xc7" + modrm + struct.pack("<I", SUPERHEX_FPS_OFFSET + 0x10) + struct.pack("<I", refresh_hz),
            b"\xc7" + modrm + struct.pack("<I", SUPERHEX_FPS_OFFSET + 0x14) + struct.pack("<I", refresh_hz),
        ]
    )


def movsd_load_rip(source_va: int, target_va: int) -> bytes:
    return b"\xf2\x0f\x10\x05" + rip_disp(source_va, target_va, 8)


def movsd_load_rip_xmm(register: int, source_va: int, target_va: int) -> bytes:
    if not 0 <= register <= 7:
        raise PatchError("only xmm0-xmm7 are supported")
    return b"\xf2\x0f\x10" + bytes([0x05 | (register << 3)]) + rip_disp(
        source_va, target_va, 8
    )


def movsd_store_rip_xmm(register: int, source_va: int, target_va: int) -> bytes:
    if not 0 <= register <= 7:
        raise PatchError("only xmm0-xmm7 are supported")
    return b"\xf2\x0f\x11" + bytes([0x05 | (register << 3)]) + rip_disp(
        source_va, target_va, 8
    )


def movss_load_rip_xmm(register: int, source_va: int, target_va: int) -> bytes:
    if not 0 <= register <= 7:
        raise PatchError("only xmm0-xmm7 are supported")
    return b"\xf3\x0f\x10" + bytes([0x05 | (register << 3)]) + rip_disp(
        source_va, target_va, 8
    )


def movsd_store_base(register_opcode: int, disp: int) -> bytes:
    return b"\xf2\x0f\x11" + bytes([register_opcode]) + struct.pack("<I", disp)


def mov_dword_rip_imm(source_va: int, target_va: int, value: int) -> bytes:
    return b"\xc7\x05" + rip_disp(source_va, target_va, 10) + struct.pack("<I", value)


def mov_qword_rip_zero(source_va: int, target_va: int) -> bytes:
    return b"\x48\xc7\x05" + rip_disp(source_va, target_va, 11) + struct.pack("<I", 0)


def patch_data_labels() -> dict[str, int]:
    data_va = SET_GAME_FRAME_RATE_VA + PATCH_DATA_REL
    labels = {
        "sim_interval": data_va,
        "double_five": data_va + 8,
        "float_one": data_va + 16,
        "float_neg_180": data_va + 20,
        "float_180": data_va + 24,
        "float_360": data_va + 28,
        "update_accumulator": PATCH_MUTABLE_DATA_VA,
        "previous_rotation_offset": PATCH_MUTABLE_DATA_VA + 8,
    }
    return labels


def build_patch_data() -> bytes:
    data = bytearray()
    data += struct.pack("<d", 1.0 / ORIGINAL_REFRESH_HZ)
    data += struct.pack("<d", 5.0)
    data += struct.pack("<f", 1.0)
    data += struct.pack("<f", -180.0)
    data += struct.pack("<f", 180.0)
    data += struct.pack("<f", 360.0)
    return bytes(data)


def append_expected_delta_store(code: bytearray, start_va: int) -> None:
    source_va = start_va + len(code)
    expected_delta_bits = struct.unpack("<I", struct.pack("<f", 1.0))[0]
    code += mov_dword_rip_imm(source_va, EXPECTED_FRAME_DELTA_VA, expected_delta_bits)


def append_accumulator_reset(code: bytearray, start_va: int, data: dict[str, int]) -> None:
    source_va = start_va + len(code)
    code += mov_qword_rip_zero(source_va, data["update_accumulator"])
    source_va = start_va + len(code)
    code += mov_dword_rip_imm(source_va, data["previous_rotation_offset"], 0)


def build_set_game_frame_rate_replacement(refresh_hz: int) -> bytes:
    start_va = SET_GAME_FRAME_RATE_VA
    data = patch_data_labels()

    code = bytearray()
    code += mov_superhex_fps_fields(0x87, ORIGINAL_REFRESH_HZ)  # [rdi + disp]
    code += movsd_load_rip(start_va + len(code), data["sim_interval"])
    code += movsd_store_base(0x87, SUPERHEX_FRAME_DELTA_OFFSET)
    append_expected_delta_store(code, start_va)
    append_accumulator_reset(code, start_va, data)
    code += b"\x57"  # push rdi
    code += b"\xbf" + struct.pack("<I", refresh_hz)
    code += call(start_va + len(code), OF_SET_FRAME_RATE_VA)
    code += b"\x5f"  # pop rdi
    code += b"\xc3"
    return bytes(code)


def build_update_hook(refresh_hz: int) -> bytes:
    start_va = SET_GAME_FRAME_RATE_VA + UPDATE_HOOK_CAVE_REL
    data = patch_data_labels()

    code = bytearray()
    code += b"\x53"  # push rbx
    code += b"\x48\x89\xfb"  # mov rbx, rdi
    code += call(start_va + len(code), OF_GET_LAST_FRAME_TIME_VA)
    code += movsd_load_rip_xmm(1, start_va + len(code), data["update_accumulator"])
    code += bytes.fromhex("f2 0f 58 c8")  # addsd xmm1, xmm0
    code += movsd_store_rip_xmm(1, start_va + len(code), data["update_accumulator"])
    code += movsd_load_rip_xmm(2, start_va + len(code), data["sim_interval"])
    code += bytes.fromhex("66 0f 2e ca")  # ucomisd xmm1, xmm2
    skip_offset = len(code)
    code += bytes.fromhex("0f 82 00 00 00 00")  # jb skip update
    code += bytes.fromhex("f2 0f 5c ca")  # subsd xmm1, xmm2
    code += movsd_store_rip_xmm(1, start_va + len(code), data["update_accumulator"])
    code += bytes.fromhex("8b 83") + struct.pack("<I", ROTATION_OFFSET)
    source_va = start_va + len(code)
    code += b"\x89\x05" + rip_disp(source_va, data["previous_rotation_offset"], 6)
    code += bytes.fromhex("66 0f 28 c2")  # movapd xmm0, xmm2
    code += jmp(start_va + len(code), UPDATE_CONTINUE_VA)
    skip_target = len(code)
    patch_near_jump(code, start_va, skip_offset, skip_target)
    code += b"\x5b"  # pop rbx
    code += b"\xc3"
    return bytes(code)


def build_draw_hook(refresh_hz: int) -> bytes:
    start_va = SET_GAME_FRAME_RATE_VA + DRAW_HOOK_CAVE_REL
    data = patch_data_labels()

    code = bytearray()
    code += b"\x53"  # push rbx
    code += bytes.fromhex("48 83 ec 30")  # stack locals, keep calls aligned
    code += bytes.fromhex("48 89 fb")  # mov rbx, rdi
    code += call(start_va + len(code), OF_GET_ELAPSED_TIME_MILLIS_VA)
    code += bytes.fromhex("89 c0")  # mov eax, eax
    code += bytes.fromhex("48 89 83") + struct.pack("<I", 0x3C710)

    code += bytes.fromhex("8b 83") + struct.pack("<I", WALL_ANGLE_OFFSET)
    code += bytes.fromhex("89 44 24 04")
    code += bytes.fromhex("8b 83") + struct.pack("<I", ROTATION_OFFSET)
    code += bytes.fromhex("89 44 24 08")
    code += bytes.fromhex("c7 44 24 0c 00 00 00 00")

    code += movsd_load_rip_xmm(0, start_va + len(code), data["update_accumulator"])
    code += bytes.fromhex("66 0f 57 d2")  # xorpd xmm2, xmm2
    code += bytes.fromhex("66 0f 2e c2")  # ucomisd xmm0, xmm2
    skip_interp_offset = len(code)
    code += bytes.fromhex("0f 86 00 00 00 00")  # jbe skip interpolation
    code += movsd_load_rip_xmm(1, start_va + len(code), data["sim_interval"])
    code += bytes.fromhex("66 0f 2e c1")  # ucomisd xmm0, xmm1
    clamp_done_offset = len(code)
    code += bytes.fromhex("76 00")  # jbe clamp done
    code += bytes.fromhex("66 0f 28 c1")  # movapd xmm0, xmm1
    patch_short_jump(code, clamp_done_offset, len(code))
    code += bytes.fromhex("f2 0f 5e c1")  # divsd xmm0, xmm1
    code += bytes.fromhex("f2 0f 11 44 24 10")  # save fraction

    # Wall angle offset decays toward zero between simulation ticks.
    code += bytes.fromhex("f3 0f 10 8b") + struct.pack("<I", WALL_ANGLE_OFFSET)
    code += bytes.fromhex("0f 57 d2")  # xorps xmm2, xmm2
    code += bytes.fromhex("0f 2f ca")  # comiss xmm1, xmm2
    skip_wall_offset = len(code)
    code += bytes.fromhex("76 00")  # jbe skip wall
    code += bytes.fromhex("f2 0f 10 44 24 10")  # movsd xmm0, [rsp+0x10]
    code += bytes.fromhex("f2 0f 59 83") + struct.pack("<I", NORMALIZED_DELTA_OFFSET)
    code += bytes.fromhex("f2 0f 5a c0")  # cvtsd2ss xmm0, xmm0
    code += bytes.fromhex("f3 0f 5c c8")  # subss xmm1, xmm0
    code += bytes.fromhex("0f 2f ca")  # comiss xmm1, xmm2
    store_wall_offset = len(code)
    code += bytes.fromhex("77 00")  # ja store wall
    code += bytes.fromhex("0f 28 ca")  # movaps xmm1, xmm2
    patch_short_jump(code, store_wall_offset, len(code))
    code += bytes.fromhex("f3 0f 11 8b") + struct.pack("<I", WALL_ANGLE_OFFSET)
    patch_short_jump(code, skip_wall_offset, len(code))

    # Rotation offset uses the previous simulation value to extrapolate smoothly.
    code += bytes.fromhex("f3 0f 10 83") + struct.pack("<I", ROTATION_OFFSET)
    code += bytes.fromhex("0f 28 c8")  # movaps xmm1, xmm0
    code += movss_load_rip_xmm(2, start_va + len(code), data["previous_rotation_offset"])
    code += bytes.fromhex("f3 0f 5c ca")  # subss xmm1, xmm2
    code += movss_load_rip_xmm(2, start_va + len(code), data["float_180"])
    code += bytes.fromhex("0f 2f ca")  # comiss xmm1, xmm2
    skip_delta_high = len(code)
    code += bytes.fromhex("76 00")
    code += movss_load_rip_xmm(2, start_va + len(code), data["float_360"])
    code += bytes.fromhex("f3 0f 5c ca")  # subss xmm1, xmm2
    patch_short_jump(code, skip_delta_high, len(code))
    code += movss_load_rip_xmm(2, start_va + len(code), data["float_neg_180"])
    code += bytes.fromhex("0f 2f ca")  # comiss xmm1, xmm2
    skip_delta_low = len(code)
    code += bytes.fromhex("73 00")
    code += movss_load_rip_xmm(2, start_va + len(code), data["float_360"])
    code += bytes.fromhex("f3 0f 58 ca")  # addss xmm1, xmm2
    patch_short_jump(code, skip_delta_low, len(code))
    code += bytes.fromhex("f2 0f 10 54 24 10")  # movsd xmm2, [rsp+0x10]
    code += bytes.fromhex("f2 0f 5a d2")  # cvtsd2ss xmm2, xmm2
    code += bytes.fromhex("f3 0f 59 ca")  # mulss xmm1, xmm2
    code += bytes.fromhex("f3 0f 58 c1")  # addss xmm0, xmm1
    code += movss_load_rip_xmm(2, start_va + len(code), data["float_360"])
    code += bytes.fromhex("0f 2f c2")  # comiss xmm0, xmm2
    skip_result_high = len(code)
    code += bytes.fromhex("72 00")
    code += bytes.fromhex("f3 0f 5c c2")  # subss xmm0, xmm2
    patch_short_jump(code, skip_result_high, len(code))
    code += bytes.fromhex("0f 57 d2")  # xorps xmm2, xmm2
    code += bytes.fromhex("0f 2f c2")  # comiss xmm0, xmm2
    skip_result_low = len(code)
    code += bytes.fromhex("73 00")
    code += movss_load_rip_xmm(2, start_va + len(code), data["float_360"])
    code += bytes.fromhex("f3 0f 58 c2")  # addss xmm0, xmm2
    patch_short_jump(code, skip_result_low, len(code))
    code += bytes.fromhex("f3 0f 11 83") + struct.pack("<I", ROTATION_OFFSET)

    # Move obstacle segments by the fractional render step, then restore them.
    code += bytes.fromhex("f3 0f 10 93") + struct.pack("<I", ACCELERATION_RAMP_OFFSET)
    code += movss_load_rip_xmm(3, start_va + len(code), data["float_one"])
    code += bytes.fromhex("0f 2f d3")  # comiss xmm2, xmm3
    high_speed_offset = len(code)
    code += bytes.fromhex("77 00")
    code += bytes.fromhex("f2 0f 10 44 24 10")  # fraction
    code += movsd_load_rip_xmm(3, start_va + len(code), data["double_five"])
    code += bytes.fromhex("f2 0f 59 c3")  # mulsd xmm0, xmm3
    code += bytes.fromhex("f3 0f 5a d2")  # cvtss2sd xmm2, xmm2
    code += bytes.fromhex("f2 0f 59 c2")  # mulsd xmm0, xmm2
    delta_ready_jump = len(code)
    code += bytes.fromhex("eb 00")
    patch_short_jump(code, high_speed_offset, len(code))
    code += bytes.fromhex("f3 0f 10 93") + struct.pack("<I", STOP_TIMER_OFFSET)
    code += bytes.fromhex("0f 57 db")  # xorps xmm3, xmm3
    code += bytes.fromhex("0f 2f d3")  # comiss xmm2, xmm3
    no_delta_offset = len(code)
    code += bytes.fromhex("77 00")
    code += bytes.fromhex("f2 0f 10 44 24 10")  # fraction
    code += bytes.fromhex("f3 0f 10 93") + struct.pack("<I", OBSTACLE_SPEED_OFFSET)
    code += bytes.fromhex("f3 0f 5a d2")  # cvtss2sd xmm2, xmm2
    code += bytes.fromhex("f2 0f 59 c2")  # mulsd xmm0, xmm2
    patch_short_jump(code, delta_ready_jump, len(code))
    code += bytes.fromhex("f2 0f 2c c0")  # cvttsd2si eax, xmm0
    store_delta_jump = len(code)
    code += bytes.fromhex("eb 00")
    patch_short_jump(code, no_delta_offset, len(code))
    code += bytes.fromhex("31 c0")  # xor eax, eax
    patch_short_jump(code, store_delta_jump, len(code))
    code += bytes.fromhex("89 44 24 0c")
    code += bytes.fromhex("85 c0")
    skip_obstacles_delta = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("8b 8b") + struct.pack("<I", ACTIVE_SEGMENT_COUNT_OFFSET)
    code += bytes.fromhex("85 c9")
    skip_obstacles_count = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("48 8d 93") + struct.pack("<I", FIRST_SEGMENT_OFFSET)
    obstacle_loop = len(code)
    code += bytes.fromhex("29 02")
    code += bytes.fromhex("29 42 04")
    code += bytes.fromhex("48 83 c2") + bytes([SEGMENT_STRIDE])
    code += bytes.fromhex("83 e9 01")
    code += b"\x75" + struct.pack("b", obstacle_loop - (len(code) + 2))
    obstacle_skip = len(code)
    patch_short_jump(code, skip_obstacles_delta, obstacle_skip)
    patch_short_jump(code, skip_obstacles_count, obstacle_skip)

    skip_interp_target = len(code)
    patch_near_jump(code, start_va, skip_interp_offset, skip_interp_target)

    code += bytes.fromhex("48 89 df")  # mov rdi, rbx
    code += call(start_va + len(code), GAMERENDER_VA)

    code += bytes.fromhex("8b 44 24 0c")
    code += bytes.fromhex("85 c0")
    skip_restore_delta = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("8b 8b") + struct.pack("<I", ACTIVE_SEGMENT_COUNT_OFFSET)
    code += bytes.fromhex("85 c9")
    skip_restore_count = len(code)
    code += bytes.fromhex("7e 00")
    code += bytes.fromhex("48 8d 93") + struct.pack("<I", FIRST_SEGMENT_OFFSET)
    restore_loop = len(code)
    code += bytes.fromhex("01 02")
    code += bytes.fromhex("01 42 04")
    code += bytes.fromhex("48 83 c2") + bytes([SEGMENT_STRIDE])
    code += bytes.fromhex("83 e9 01")
    code += b"\x75" + struct.pack("b", restore_loop - (len(code) + 2))
    restore_skip = len(code)
    patch_short_jump(code, skip_restore_delta, restore_skip)
    patch_short_jump(code, skip_restore_count, restore_skip)

    code += bytes.fromhex("8b 44 24 04")
    code += bytes.fromhex("89 83") + struct.pack("<I", WALL_ANGLE_OFFSET)
    code += bytes.fromhex("8b 44 24 08")
    code += bytes.fromhex("89 83") + struct.pack("<I", ROTATION_OFFSET)
    code += bytes.fromhex("48 83 c4 30")
    code += b"\x5b"
    code += b"\xc3"
    return bytes(code)


def build_of_set_frame_rate_hook(refresh_hz: int) -> bytes:
    start_va = SET_GAME_FRAME_RATE_VA + OF_SET_FRAME_RATE_CAVE_REL
    code = bytearray()
    code += b"\x48\x8b\x0d" + rip_disp(start_va + len(code), WINDOW_GLOBAL_VA, 7)
    code += b"\xbf" + struct.pack("<I", refresh_hz)
    code += b"\x31\xd2"  # xor edx, edx
    code += b"\x48\x8b\x81" + struct.pack("<I", WINDOW_FREQ_OFFSET)
    code += b"\x48\xf7\xf7"  # div rdi
    code += b"\x48\x89\x81" + struct.pack("<I", WINDOW_FRAME_INTERVAL_OFFSET)
    code += b"\xc3"
    return bytes(code)


def build_patch_region(refresh_hz: int) -> bytes:
    region = bytearray(b"\x90" * PATCH_REGION_SIZE)
    set_frame_rate = build_set_game_frame_rate_replacement(refresh_hz)
    update_hook = build_update_hook(refresh_hz)
    of_set_frame_rate = build_of_set_frame_rate_hook(refresh_hz)
    patch_data = build_patch_data()

    for name, start, payload in (
        ("setGameFrameRate replacement", 0, set_frame_rate),
        ("update hook", UPDATE_HOOK_CAVE_REL, update_hook),
        ("ofSetFrameRate hook", OF_SET_FRAME_RATE_CAVE_REL, of_set_frame_rate),
        ("patch data", PATCH_DATA_REL, patch_data),
    ):
        if start + len(payload) > PATCH_REGION_SIZE:
            raise PatchError(f"internal Linux {name} exceeds patch region")

    metadata_length = len(PATCH_MAGIC) + 4 + 4 + 8 + 4
    ranges = [
        ("setGameFrameRate replacement", 0, len(set_frame_rate)),
        ("update hook", UPDATE_HOOK_CAVE_REL, UPDATE_HOOK_CAVE_REL + len(update_hook)),
        (
            "ofSetFrameRate hook",
            OF_SET_FRAME_RATE_CAVE_REL,
            OF_SET_FRAME_RATE_CAVE_REL + len(of_set_frame_rate),
        ),
        ("patch data", PATCH_DATA_REL, PATCH_DATA_REL + len(patch_data)),
        ("metadata", PATCH_METADATA_REL, PATCH_METADATA_REL + metadata_length),
    ]
    ordered_ranges = sorted(ranges, key=lambda item: item[1])
    for (left_name, left_start, left_end), (right_name, right_start, right_end) in zip(
        ordered_ranges, ordered_ranges[1:]
    ):
        if left_end > right_start:
            raise PatchError(
                f"internal Linux {left_name} overlaps {right_name}: "
                f"{left_start:#x}-{left_end:#x} vs {right_start:#x}-{right_end:#x}"
            )

    region[: len(set_frame_rate)] = set_frame_rate
    region[UPDATE_HOOK_CAVE_REL : UPDATE_HOOK_CAVE_REL + len(update_hook)] = update_hook
    region[
        OF_SET_FRAME_RATE_CAVE_REL : OF_SET_FRAME_RATE_CAVE_REL + len(of_set_frame_rate)
    ] = of_set_frame_rate
    region[PATCH_DATA_REL : PATCH_DATA_REL + len(patch_data)] = patch_data

    metadata = bytearray()
    metadata += PATCH_MAGIC
    metadata += struct.pack("<I", PATCH_VERSION)
    metadata += struct.pack("<I", refresh_hz)
    metadata += struct.pack("<d", 1.0 / ORIGINAL_REFRESH_HZ)
    metadata += struct.pack("<f", 1.0)
    region[PATCH_METADATA_REL : PATCH_METADATA_REL + len(metadata)] = metadata
    return bytes(region)


def build_constructor_timer_patch(refresh_hz: int) -> bytes:
    code = bytearray()
    code += bytes.fromhex("c7 83 f8 04 00 00 00 00 00 00")
    code += bytes.fromhex("c6 83 38 05 00 00 00")
    code += bytes.fromhex("c6 83 39 05 00 00 00")
    code += bytes.fromhex("c6 03 01")
    code += b"\x48\x8b\x83" + struct.pack("<I", WINDOW_FREQ_OFFSET)
    code += b"\xbf" + struct.pack("<I", refresh_hz)
    code += b"\x31\xd2"
    code += b"\x48\xf7\xf7"
    code += b"\x48\x89\x83" + struct.pack("<I", WINDOW_FRAME_INTERVAL_OFFSET)
    code += b"\x90" * (CONSTRUCTOR_TIMER_SIZE - len(code))
    if len(code) != CONSTRUCTOR_TIMER_SIZE:
        raise PatchError("internal constructor patch size mismatch")
    return bytes(code)


def patch_sites_for(refresh_hz: int) -> dict[str, bytes]:
    return {
        "setGameFrameRate cave": build_patch_region(refresh_hz),
        "update hook": jump_patch(
            UPDATE_HOOK_VA,
            SET_GAME_FRAME_RATE_VA + UPDATE_HOOK_CAVE_REL,
            UPDATE_HOOK_SIZE,
        ),
        "ofSetFrameRate hook": jump_patch(
            OF_SET_FRAME_RATE_VA,
            SET_GAME_FRAME_RATE_VA + OF_SET_FRAME_RATE_CAVE_REL,
            OF_SET_FRAME_RATE_SIZE,
        ),
        "constructor timer": build_constructor_timer_patch(refresh_hz),
        "expected frame delta": struct.pack("<f", 1.0),
    }


def metadata_refresh_hz(data: bytes | bytearray) -> int | None:
    offset = SET_GAME_FRAME_RATE_OFFSET + PATCH_METADATA_REL
    raw = slice_at(data, offset, len(PATCH_MAGIC) + 8)
    if len(raw) != len(PATCH_MAGIC) + 8 or not raw.startswith(PATCH_MAGIC):
        return None
    version, refresh_hz = struct.unpack("<II", raw[len(PATCH_MAGIC) : len(PATCH_MAGIC) + 8])
    if version != PATCH_VERSION or not is_supported_refresh_hz(refresh_hz):
        return None
    return refresh_hz


def legacy_timing_scale_refresh_hz(data: bytes | bytearray) -> int | None:
    offset = SET_GAME_FRAME_RATE_OFFSET + LEGACY_PATCH_METADATA_REL
    raw = slice_at(data, offset, len(PATCH_MAGIC) + 8)
    if len(raw) != len(PATCH_MAGIC) + 8 or not raw.startswith(PATCH_MAGIC):
        return None
    version, refresh_hz = struct.unpack("<II", raw[len(PATCH_MAGIC) : len(PATCH_MAGIC) + 8])
    if version != LEGACY_TIMING_SCALE_PATCH_VERSION:
        return None
    if refresh_hz == ORIGINAL_REFRESH_HZ or refresh_hz < 120 or refresh_hz % 60:
        return None
    old_update_hook = jump_patch(
        UPDATE_HOOK_VA,
        SET_GAME_FRAME_RATE_VA + LEGACY_UPDATE_HOOK_CAVE_REL,
        UPDATE_HOOK_SIZE,
    )
    old_of_set_hook = jump_patch(
        OF_SET_FRAME_RATE_VA,
        SET_GAME_FRAME_RATE_VA + LEGACY_OF_SET_FRAME_RATE_CAVE_REL,
        OF_SET_FRAME_RATE_SIZE,
    )
    if (
        slice_at(data, UPDATE_HOOK_OFFSET, len(old_update_hook)) == old_update_hook
        and slice_at(data, OF_SET_FRAME_RATE_OFFSET, len(old_of_set_hook)) == old_of_set_hook
    ):
        return refresh_hz
    return None


def all_patched_sites_match(data: bytes | bytearray, refresh_hz: int) -> bool:
    sites = patch_sites_for(refresh_hz)
    checks = [
        (SET_GAME_FRAME_RATE_OFFSET, sites["setGameFrameRate cave"]),
        (UPDATE_HOOK_OFFSET, sites["update hook"]),
        (OF_SET_FRAME_RATE_OFFSET, sites["ofSetFrameRate hook"]),
        (CONSTRUCTOR_TIMER_OFFSET, sites["constructor timer"]),
        (EXPECTED_FRAME_DELTA_OFFSET, sites["expected frame delta"]),
    ]
    return all(slice_at(data, offset, len(expected)) == expected for offset, expected in checks)


def original_sites_match(data: bytes | bytearray) -> bool:
    checks = [
        (UPDATE_HOOK_OFFSET, ORIGINAL_UPDATE_PROLOGUE),
        (
            DRAW_HOOK_OFFSET,
            bytes.fromhex(
                "53 48 89 fb e8 a7 be 00 00 89 c0 48 89 df 48 89 83 "
                "10 c7 03 00 5b e9 35 ec ff ff"
            ),
        ),
        (OF_SET_FRAME_RATE_OFFSET, ORIGINAL_OF_SET_FRAME_RATE),
        (CONSTRUCTOR_TIMER_OFFSET, ORIGINAL_CONSTRUCTOR_TIMER),
        (EXPECTED_FRAME_DELTA_OFFSET, ORIGINAL_EXPECTED_FRAME_DELTA),
    ]
    return all(slice_at(data, offset, len(expected)) == expected for offset, expected in checks)


def is_elf64_linux_executable(data: bytes | bytearray) -> bool:
    return (
        len(data) >= 0x40
        and data[:4] == b"\x7fELF"
        and data[4] == 2
        and data[5] == 1
        and data[0x12:0x14] == b"\x3e\x00"
    )


def analyze_image(data: bytes) -> ImageState:
    digest = sha256_bytes(data)
    known_hash = digest == SUPPORTED_EXE_SHA256 and len(data) == SUPPORTED_EXE_SIZE

    if not is_elf64_linux_executable(data):
        return ImageState("unsupported", digest, len(data), False, reason="not an ELF64 x86-64 executable")

    patched_refresh_hz = metadata_refresh_hz(data)
    if patched_refresh_hz is not None:
        if all_patched_sites_match(data, patched_refresh_hz):
            return ImageState("patched", digest, len(data), True, refresh_hz=patched_refresh_hz)
        return ImageState(
            "conflict",
            digest,
            len(data),
            False,
            refresh_hz=patched_refresh_hz,
            reason="Linux patch metadata exists, but patch sites do not match this patcher",
        )

    legacy_refresh_hz = legacy_timing_scale_refresh_hz(data)
    if legacy_refresh_hz is not None:
        return ImageState(
            "legacy-timing-scaling",
            digest,
            len(data),
            True,
            refresh_hz=legacy_refresh_hz,
            reason="old Linux patch scales the game frame delta instead of using fixed 60 FPS simulation",
        )

    if original_sites_match(data):
        return ImageState("original", digest, len(data), known_hash, refresh_hz=ORIGINAL_REFRESH_HZ)

    return ImageState(
        "unsupported",
        digest,
        len(data),
        False,
        reason="expected Linux Neo patch signatures were not found",
    )


def patch_image(data: bytes, refresh_hz: int, force: bool = False) -> tuple[bytes, ImageState, bool]:
    validate_refresh_hz(refresh_hz)
    state = analyze_image(data)

    if refresh_hz == ORIGINAL_REFRESH_HZ:
        restored, restored_state, changed = unpatch_image(data)
        return restored, restored_state, changed

    if state.status == "patched":
        patched = bytearray(data)
    elif state.status == "original":
        if not state.supported_signatures and not force:
            raise PatchError(
                "unsupported Linux executable hash/signatures. Re-run with --force only if this "
                "is the Neo Linux Steam build and you accept patching by byte signatures."
            )
        patched = bytearray(data)
    else:
        raise PatchError(state.reason or f"cannot patch executable in state: {state.status}")

    sites = patch_sites_for(refresh_hz)
    patched[
        SET_GAME_FRAME_RATE_OFFSET : SET_GAME_FRAME_RATE_OFFSET + len(sites["setGameFrameRate cave"])
    ] = sites["setGameFrameRate cave"]
    patched[UPDATE_HOOK_OFFSET : UPDATE_HOOK_OFFSET + len(sites["update hook"])] = sites["update hook"]
    patched[
        OF_SET_FRAME_RATE_OFFSET : OF_SET_FRAME_RATE_OFFSET + len(sites["ofSetFrameRate hook"])
    ] = sites["ofSetFrameRate hook"]
    patched[
        CONSTRUCTOR_TIMER_OFFSET : CONSTRUCTOR_TIMER_OFFSET + len(sites["constructor timer"])
    ] = sites["constructor timer"]
    patched[
        EXPECTED_FRAME_DELTA_OFFSET : EXPECTED_FRAME_DELTA_OFFSET + len(sites["expected frame delta"])
    ] = sites["expected frame delta"]

    new_data = bytes(patched)
    new_state = analyze_image(new_data)
    if new_state.status != "patched" or new_state.refresh_hz != refresh_hz:
        raise PatchError(new_state.reason or "failed to apply Linux patch")
    return new_data, new_state, new_state.sha256 != state.sha256


def unpatch_image(data: bytes) -> tuple[bytes, ImageState, bool]:
    state = analyze_image(data)
    if state.status == "original":
        return data, state, False
    if state.status == "patched":
        raise PatchError(
            "restore requires the .bak backup for the Neo Linux patcher because the patch reuses "
            "part of the original setGameFrameRate function as code space"
        )
    raise PatchError(state.reason or f"cannot unpatch executable in state: {state.status}")


def backup_path_for(exe_path: Path) -> Path:
    return exe_path.with_name(f"{exe_path.name}.bak")


def legacy_backup_paths(exe_path: Path) -> list[Path]:
    return sorted(exe_path.parent.glob(f"{exe_path.name}.bak.*"))


def path_mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return None


def executable_mode(mode: int | None) -> int:
    if mode is None:
        return DEFAULT_EXE_MODE
    if mode & 0o111:
        return mode

    execute_bits = 0
    if mode & 0o400:
        execute_bits |= 0o100
    if mode & 0o040:
        execute_bits |= 0o010
    if mode & 0o004:
        execute_bits |= 0o001
    return mode | execute_bits or DEFAULT_EXE_MODE


def write_image(path: Path, data: bytes, mode: int | None = None) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    final_mode = mode if mode is not None else path_mode(path)
    try:
        tmp_path.write_bytes(data)
        if final_mode is not None:
            os.chmod(tmp_path, final_mode)
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def backup_is_valid_original(data: bytes, force: bool = False) -> bool:
    state = analyze_image(data)
    return state.status == "original" and (state.supported_signatures or force)


def backup_state_for_restore(backup_data: bytes, current_state: ImageState) -> ImageState | None:
    backup_state = analyze_image(backup_data)
    if backup_state.status != "original":
        return None
    if backup_state.supported_signatures:
        return backup_state
    if current_state.status == "patched":
        return backup_state
    return None


def original_image_for_backup(data: bytes, force: bool) -> bytes:
    if backup_is_valid_original(data, force=force):
        return data
    raise PatchError(
        "could not create a Linux backup from the current executable because it is not a "
        "valid original image"
    )


def require_existing_backup_file(exe_path: Path, force: bool) -> None:
    backup_path = backup_path_for(exe_path)
    if not backup_path.exists():
        raise PatchError(
            "--no-backup is not supported for the Neo Linux patcher unless a valid .bak "
            "already exists, because restore needs the original setGameFrameRate bytes"
        )

    backup_data = backup_path.read_bytes()
    if not backup_is_valid_original(backup_data, force=force):
        raise PatchError(f"backup exists but is not a valid original for this build: {backup_path}")


def ensure_backup_file(exe_path: Path, current_data: bytes, force: bool) -> None:
    backup_path = backup_path_for(exe_path)
    exe_mode = executable_mode(path_mode(exe_path))
    if backup_path.exists():
        backup_data = backup_path.read_bytes()
        if backup_is_valid_original(backup_data, force=force):
            backup_mode = path_mode(backup_path)
            if backup_mode is None or not backup_mode & 0o111:
                os.chmod(backup_path, exe_mode)
            print(f"Backup already exists: {backup_path}")
            return

        replacement_data = original_image_for_backup(current_data, force=force)
        write_image(backup_path, replacement_data, mode=exe_mode)
        print(f"Backup replaced: {backup_path}")
        return

    for legacy_path in legacy_backup_paths(exe_path):
        legacy_data = legacy_path.read_bytes()
        if backup_is_valid_original(legacy_data, force=force):
            shutil.copy2(legacy_path, backup_path)
            os.chmod(backup_path, executable_mode(path_mode(backup_path)))
            print(f"Backup migrated: {backup_path} (from {legacy_path.name})")
            return

    write_image(backup_path, original_image_for_backup(current_data, force=force), mode=exe_mode)
    print(f"Backup written: {backup_path}")


def patch_file(exe_path: Path, refresh_hz: int, force: bool, backup: bool) -> ImageState:
    if refresh_hz == ORIGINAL_REFRESH_HZ:
        return unpatch_file(exe_path)

    current = exe_path.read_bytes()
    exe_mode = executable_mode(path_mode(exe_path))
    if backup:
        ensure_backup_file(exe_path, current, force=force)
    else:
        require_existing_backup_file(exe_path, force=force)

    source = current
    current_state = analyze_image(current)
    if current_state.status in {"legacy-timing-scaling", "conflict"}:
        backup_path = backup_path_for(exe_path)
        backup_data = backup_path.read_bytes()
        backup_state = analyze_image(backup_data)
        if backup_state.status != "original" or not (backup_state.supported_signatures or force):
            raise PatchError(f"backup exists but is not a valid original for this build: {backup_path}")
        source = backup_data

    patched, state, changed = patch_image(source, refresh_hz=refresh_hz, force=force)
    if changed or patched != current:
        write_image(exe_path, patched, mode=exe_mode)
    return state


def unpatch_file(exe_path: Path) -> ImageState:
    current_data = exe_path.read_bytes()
    current_mode = executable_mode(path_mode(exe_path))
    current_state = analyze_image(current_data)
    backup_path = backup_path_for(exe_path)
    if backup_path.exists():
        backup_data = backup_path.read_bytes()
        backup_state = backup_state_for_restore(backup_data, current_state)
        if backup_state is not None:
            restore_mode = executable_mode(path_mode(backup_path) or current_mode)
            if current_data != backup_data:
                write_image(exe_path, backup_data, mode=restore_mode)
            else:
                os.chmod(exe_path, restore_mode)
            return backup_state

        if current_state.status == "original":
            write_image(backup_path, current_data, mode=current_mode)
            return current_state
        raise PatchError(f"backup exists but is not a valid original for this build: {backup_path}")

    restored, state, changed = unpatch_image(current_data)
    if changed:
        write_image(exe_path, restored, mode=current_mode)
    return state


def diagnose_file(
    exe_path: Path,
    refresh_hz: int,
    duration_seconds: float,
    warmup_seconds: float,
    force: bool,
) -> DiagnosticResult:
    raise PatchError("runtime diagnostics are not implemented for the Neo Linux patcher yet")


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
    return "\n".join(
        [
            f"Measured duration: {result.duration_seconds:.2f}s",
            f"Update calls: {result.update_count} ({result.update_count / duration:.1f}/s)",
            f"Draw calls: {result.draw_count} ({result.draw_count / duration:.1f}/s)",
            f"Swap calls: {result.swap_count} ({result.swap_count / duration:.1f}/s)",
        ]
    )
