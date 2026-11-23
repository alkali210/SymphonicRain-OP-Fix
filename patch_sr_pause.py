"""Build SR_PAUSE_FIX.EXE with the movie fix, pause menu, and system shortcuts.

Build dependencies: Python, keystone-engine, Pillow and the Windows Segoe UI
fonts. The resulting executable runs directly from the game directory.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import struct

from patch_sr_op import TEXT_ADDRESS, TEXT_FILE_OFFSET, patch_executable, relative_instruction


ROOT = Path(__file__).resolve().parent
OP_FIX_SHA256 = "66f4a24db63645a5ccf133087570169f20971a434ed9805bce3e3d7ef6814f3f"
MENU_SIZE = (300, 132)
MENU_LEFT = (640 - MENU_SIZE[0]) // 2
MENU_TOP = (480 - MENU_SIZE[1]) // 2
KEYBOARD_COOPERATIVE_FLAGS = 0x43C25C
DISCL_FOREGROUND = 0x04
DISCL_NONEXCLUSIVE = 0x02
HOOKS = (
    # Music update immediately after establishing the original stack frame.
    (0x441039, "e8222d0000 f683311f000080 7417", b"\xe9", 0),
    # Song clock, independent of the game's frame timer.
    (0x419191, "01880c050000", b"\xe9", 0x400),
    # Main panel composition, before the surface is presented.
    (0x4195B5, "e8aa120c00", b"\xe8", 0x500),
    (0x419CDF, "e8ac0b0c00", b"\xe8", 0x540),
    (0x419CB0, "e8bb050c00", b"\xe8", 0x580),
    # Start and cleanup of the common performance routine.
    (0x422B29, "e89ee40100", b"\xe8", 0x700),
    (0x422C12, "e8cde30100", b"\xe8", 0x740),
)
IMAGE_OFFSET = 0xA00


def aligned(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def menu_pixels(selection):
    from PIL import Image, ImageDraw, ImageFont

    fonts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
    title = ImageFont.truetype(str(fonts / "segoeuib.ttf"), 25)
    button = ImageFont.truetype(str(fonts / "segoeuib.ttf"), 18)
    help_text = ImageFont.truetype(str(fonts / "segoeui.ttf"), 13)
    image = Image.new("RGB", MENU_SIZE, "#101a24")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 299, 131), outline="#b2c2cf", width=1)
    draw.text((150, 28), "Paused", font=title, fill="#fff7e6", anchor="mm")
    for index, label in enumerate(("Resume", "Retry")):
        left = 17 + index * 137
        selected = index == selection
        draw.rounded_rectangle(
            (left, 52, left + 128, 91), radius=5,
            fill="#f3d894" if selected else "#253649",
            outline="#f3d894" if selected else "#60758a",
        )
        draw.text(
            (left + 64, 71), label, font=button, anchor="mm",
            fill="#161d27" if selected else "#f3ead8",
        )
    draw.text(
        (150, 112), "← / →  Select     Enter  Confirm     Esc  Resume",
        font=help_text, fill="#d1dbe5", anchor="mm",
    )
    return image.tobytes("raw", "BGR")


def build_routine(code_address, data_address, image_bytes):
    from keystone import KS_ARCH_X86, KS_MODE_32, Ks

    width, height = MENU_SIZE
    source = (ROOT / "sr_pause.asm").read_text(encoding="ascii").format(
        pause_state=hex(data_address),
        previous_keys=hex(data_address + 1),
        menu_drawn=hex(data_address + 2),
        effects=hex(data_address + 4),
        paint_menu=hex(code_address + 0x600),
        images=hex(code_address + IMAGE_OFFSET),
        image_bytes=image_bytes,
        width=width,
        height=height,
        pitch=width * 3,
        left=MENU_LEFT,
        top=MENU_TOP,
        right=MENU_LEFT + width - 1,
        bottom=MENU_TOP + height - 1,
    )
    # Keystone interprets semicolons as statement separators.
    source = "\n".join(line.split(";", 1)[0] for line in source.splitlines())
    assembler = Ks(KS_ARCH_X86, KS_MODE_32)
    first, *sections = re.split(r"^\.org (0x[0-9a-f]+)$", source, flags=re.MULTILINE)
    sections = ["0x0", first, *sections]
    result = bytearray()
    for address, instructions in zip(sections[::2], sections[1::2]):
        offset = int(address, 16)
        if offset < len(result):
            raise ValueError("Pause routines overlap.")
        code, _ = assembler.asm(instructions, addr=code_address + offset, as_bytes=True)
        result.extend(bytes(offset - len(result)))
        result.extend(code)
    if len(result) > IMAGE_OFFSET:
        raise ValueError("Pause routines exceed their reserved code area.")
    return result.ljust(IMAGE_OFFSET, b"\0")


def add_pause_sections(executable):
    pe_offset, = struct.unpack_from("<I", executable, 0x3C)
    coff = pe_offset + 4
    section_count, = struct.unpack_from("<H", executable, coff + 2)
    optional_size, = struct.unpack_from("<H", executable, coff + 16)
    optional = coff + 20
    image_base, section_alignment, file_alignment = struct.unpack_from("<3I", executable, optional + 28)
    code_rva, header_size = struct.unpack_from("<2I", executable, optional + 56)
    next_header = optional + optional_size + section_count * 40
    if next_header + 80 > header_size or any(executable[next_header:next_header + 80]):
        raise ValueError("The PE section table has no room for the patch sections.")

    images = [menu_pixels(selection) for selection in (0, 1)]
    code_size = IMAGE_OFFSET + sum(map(len, images))
    data_rva = aligned(code_rva + code_size, section_alignment)
    code_address = image_base + code_rva
    routine = build_routine(code_address, image_base + data_rva, len(images[0]))

    code_raw = aligned(len(executable), file_alignment)
    code_raw_size = aligned(code_size, file_alignment)
    data_raw = code_raw + code_raw_size
    data_raw_size = file_alignment
    header = struct.Struct("<8s6I2HI")
    header.pack_into(executable, next_header, b".srpause", code_size, code_rva,
                     code_raw_size, code_raw, 0, 0, 0, 0, 0x60000020)
    header.pack_into(executable, next_header + 40, b".srstate", 8, data_rva,
                     data_raw_size, data_raw, 0, 0, 0, 0, 0xC0000040)
    struct.pack_into("<H", executable, coff + 2, section_count + 2)
    for offset, extra in ((4, code_raw_size), (8, data_raw_size)):
        size, = struct.unpack_from("<I", executable, optional + offset)
        struct.pack_into("<I", executable, optional + offset, size + extra)
    struct.pack_into("<II", executable, optional + 56,
                     aligned(data_rva + 8, section_alignment), header_size)
    struct.pack_into("<I", executable, optional + 64, 0)  # Stale PE checksum.

    executable.extend(bytes(code_raw - len(executable)))
    executable.extend(routine)
    executable.extend(b"".join(images))
    executable.extend(bytes(data_raw + data_raw_size - len(executable)))
    return code_address


def patch_pause(source):
    if hashlib.sha256(source).hexdigest() == OP_FIX_SHA256:
        executable = bytearray(source)
    else:
        executable = patch_executable(source)

    # The music keyboard used FOREGROUND | EXCLUSIVE | NOWINKEY (0x15).
    # Foreground, nonexclusive DirectInput preserves buffered note input and
    # lets Windows handle shortcuts while the keyboard is acquired.
    flags_offset = TEXT_FILE_OFFSET + KEYBOARD_COOPERATIVE_FLAGS - TEXT_ADDRESS
    if executable[flags_offset - 1:flags_offset + 1] != b"\x6a\x15":
        raise ValueError("Unexpected music keyboard cooperative flags.")
    executable[flags_offset] = DISCL_FOREGROUND | DISCL_NONEXCLUSIVE

    code_address = add_pause_sections(executable)
    for address, expected, opcode, entry_offset in HOOKS:
        original = bytes.fromhex(expected)
        offset = TEXT_FILE_OFFSET + address - TEXT_ADDRESS
        if executable[offset:offset + len(original)] != original:
            raise ValueError(f"Unexpected game code at 0x{address:x}.")
        branch = relative_instruction(opcode, address, code_address + entry_offset)
        executable[offset:offset + len(original)] = branch.ljust(len(original), b"\x90")
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", type=Path, default=ROOT / "SR.EXE")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.source.with_name("SR_PAUSE_FIX.EXE")
    try:
        patched = patch_pause(args.source.read_bytes())
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
    except (OSError, ValueError, ImportError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Patched: {output}")


if __name__ == "__main__":
    main()
