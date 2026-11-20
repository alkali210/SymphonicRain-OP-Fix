"""Build a patched copy of the unpacked Simplified Chinese SR.EXE."""

import argparse
import hashlib
from pathlib import Path
import struct


SOURCE_SHA256 = "1747a9e7f689be0c73b5496f8c8eeca3410b46329ab9331c05250f12580eec61"

# This build maps .text from file offset 0x600 to virtual address 0x401000.
TEXT_FILE_OFFSET = 0x600
TEXT_ADDRESS = 0x401000
MOVIE_PRESENT_CALL = 0x4222B5
PRESENT = 0x41A84C
SLEEP_THUNK = 0x58E516
PATCH_ROUTINE = 0x58ED00


def relative_instruction(opcode, address, target):
    return opcode + struct.pack("<i", target - address - len(opcode) - 4)


def patch_executable(original):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError("Unsupported SR.EXE (SHA-256 mismatch).")

    # EAX holds MainForm at the original call. The DirectDraw context's
    # fullscreen flag selects the existing Present path via a tail jump.
    routine = bytes.fromhex(
        "8b 90 e8 04 00 00 "  # mov edx, [eax+0x4e8]
        "80 7a 34 00"         # cmp byte ptr [edx+0x34], 0
    )
    routine += relative_instruction(b"\x0f\x85", PATCH_ROUTINE + len(routine), PRESENT)

    # The movie's frame-ready callback already calls Present. In windowed
    # mode this iteration only needs to yield before polling the next sample.
    routine += b"\x6a\x03"  # push 3
    routine += relative_instruction(b"\xe8", PATCH_ROUTINE + len(routine), SLEEP_THUNK)
    routine += b"\xc3"      # ret (Sleep removes its stdcall argument)

    call_offset = TEXT_FILE_OFFSET + MOVIE_PRESENT_CALL - TEXT_ADDRESS
    routine_offset = TEXT_FILE_OFFSET + PATCH_ROUTINE - TEXT_ADDRESS
    original_call = relative_instruction(b"\xe8", MOVIE_PRESENT_CALL, PRESENT)
    if original[call_offset:call_offset + 5] != original_call:
        raise ValueError("Unexpected movie Present call.")
    if original[routine_offset:routine_offset + len(routine)] != bytes(len(routine)):
        raise ValueError("Expected empty .text padding.")

    patched = bytearray(original)
    patched[call_offset:call_offset + 5] = relative_instruction(
        b"\xe8", MOVIE_PRESENT_CALL, PATCH_ROUTINE
    )
    patched[routine_offset:routine_offset + len(routine)] = routine
    return patched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?", help="Path to the original SR.EXE")
    parser.add_argument("-o", "--output", type=Path, help="Path for the patched copy")
    args = parser.parse_args()
    source = args.source or Path(__file__).resolve().with_name("SR.EXE")
    output = args.output or source.with_name("SR_OP_FIX.EXE")

    try:
        patched = patch_executable(source.read_bytes())
        try:
            stream = output.open("xb")
        except FileExistsError:
            if output.read_bytes() != patched:
                raise
            print(f"Already patched: {output}")
            return
        try:
            with stream:
                stream.write(patched)
        except OSError:
            output.unlink()
            raise
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Patched: {output}")


if __name__ == "__main__":
    main()
