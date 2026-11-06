#!/usr/bin/env python3
# patch_watusi.py — 静态修补 libWatusiToolsSL.dylib 的 PAC 崩溃调用点
# 1) 校验崩溃报告中 LR 指向的返回地址前 4 字节确为 BL 指令，再 NOP
# 2) 修补 Watusi.dylib 的 WSVendor 死依赖（原地改写字符串，不改 cmdsize）
import struct, sys, os

SRC = os.path.join(os.path.dirname(__file__), "src")
OUT = os.path.join(os.path.dirname(__file__), "out")
NOP = 0xD503201F  # ARM64 NOP
RET = 0xD65F03C0  # ARM64 RET


def is_bl(insn: int) -> bool:
    return (insn & 0xFC000000) == 0x94000000  # BL


def segments(data):
    magic, ncmds = struct.unpack_from("<II", data, 0)
    assert magic == 0xFEEDFACF, "not arm64 mach-o"
    off = 32  # mach_header_64 共 32 字节，load commands 从这里开始
    segs = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off + 8: off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += size
    return segs


def vm_to_file(segs, vmaddr_off):
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if vmaddr <= vmaddr_off < vmaddr + vmsize:
            return fileoff + (vmaddr_off - vmaddr)
    return None


def patch_dylib(name, vm_offsets):
    path = os.path.join(SRC, name)
    data = bytearray(open(path, "rb").read())
    segs = segments(data)
    print(f"\n== {name} ==  size={len(data)}")
    for s in segs[:6]:
        print(f"   seg {s[0]:<16} vmaddr=0x{s[1]:x} fileoff=0x{s[3]:x} size=0x{s[4]:x}")
    for vmoff in vm_offsets:
        foff = vm_to_file(segs, vmoff)
        if foff is None:
            print(f"   ❌ 0x{vmoff:x} 不在映射区间")
            continue
        insn = struct.unpack_from("<I", data, foff)[0]
        kind = "BL" if is_bl(insn) else f"0x{insn:08x}"
        # 崩溃报告 LR=返回地址 → 调用点在 LR-4
        call_vmoff = vmoff - 4
        call_foff = vm_to_file(segs, call_vmoff)
        cinsn = struct.unpack_from("<I", data, call_foff)[0]
        print(f"   帧返回 0x{vmoff:x} (文件0x{foff:x}) insn={kind}")
        if is_bl(cinsn):
            target = (cinsn & 0x03FFFFFF)
            disp = target << 2
            if disp & 0x08000000: disp -= 0x10000000
            print(f"   ✅ 调用点 0x{call_vmoff:x} (文件0x{call_foff:x}) = BL → 0x{call_vmoff + disp:x}，改为 NOP")
            struct.pack_into("<I", data, call_foff, NOP)
        else:
            print(f"   ⚠️ 调用点 0x{call_vmoff:x} 不是 BL (0x{cinsn:08x})，跳过（避免破坏代码）")
    outp = os.path.join(OUT, name)
    open(outp, "wb").write(data)
    print(f"   💾 已写出 {outp}")


def fix_wsvendor(name):
    path = os.path.join(SRC, name)
    data = bytearray(open(path, "rb").read())
    old = b"@rpath/WSVendor.framework/WSVendor\x00"
    new = b"/usr/lib/libobjc.A.dylib\x00"
    idx = data.find(old)
    if idx < 0:
        print(f"\n== {name} == 未发现 WSVendor 依赖，跳过")
        return
    pad = len(old) - len(new)
    data[idx: idx + len(old)] = new + b"\x00" * pad
    outp = os.path.join(OUT, name)
    open(outp, "wb").write(data)
    print(f"\n== {name} == ✅ WSVendor 依赖已改指 /usr/lib/libobjc.A.dylib (原地补零，cmdsize 不变)")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    # 崩溃栈帧返回地址（VM 偏移）：真正 BL 在其前 4 字节
    patch_dylib("libWatusiToolsSL.dylib", [170060, 83548, 385496])
    fix_wsvendor("Watusi.dylib")
