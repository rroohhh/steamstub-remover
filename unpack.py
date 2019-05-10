from elftools.elf.elffile import ELFFile

import logging
import sys
import os
import struct
from logging import *
from collections import namedtuple
import sys

from Crypto.Cipher import AES

def dump_hex(data):
    def to_hex(data):
        try:
            if dump_hex.limit == 0 or len(data) < dump_hex.limit:
                return data.hex()
            else:
                return "{}... ({} bytes total)".format(
                    data[:dump_hex.limit].hex(), len(data))
        except AttributeError:
            return to_hex(bytes(data))
    return to_hex(data)
dump_hex.limit = 64

class ANSIColorFormatter(logging.Formatter):
    LOG_COLORS = {
        "TRACE"   : "\033[37m",
        "DEBUG"   : "\033[36m",
        "INFO"    : "\033[1;37m",
        "WARNING" : "\033[1;33m",
        "ERROR"   : "\033[1;31m",
        "CRITICAL": "\033[1;41m",
    }

    def format(self, record):
        color = self.LOG_COLORS.get(record.levelname, "")
        record.name = record.name.replace("._", ".")
        return "{}{}\033[0m".format(color, super().format(record))

log = logging.getLogger()
log.setLevel(DEBUG)

handler = logging.StreamHandler(sys.stdout)
formatter_args = {"fmt": "{levelname[0]:s}: {name:s}: {message:s}", "style": "{"}
handler = logging.StreamHandler()
handler.setFormatter(ANSIColorFormatter(**formatter_args))
log.addHandler(handler)

binary = sys.argv[1]

with open(binary, "rb") as f:
    e = ELFFile(f)
    entrypoint = e.header['e_entry']

    log.debug("binary contains sections:")
    log.debug("        name                 type              addr         size      offset")


    for section in e.iter_sections():
        addr = section['sh_addr']
        type = section['sh_type']
        offs = section['sh_offset']
        size = section['sh_size']
        log.debug("section {: <20} {: <17} 0x{: <10x} 0x{: <7x} 0x{: <8x}".format(section.name, type, addr, size, offs))


    log.debug("found entry point 0x{:x}".format(entrypoint))

    bind = e.get_section_by_name('.bind')
   
    if bind is None:
        log.error("could not find \".bind\" section, either this version of steamstub is not supported or this is not a steamstub binary")
        exit(-1)

    bind_addr = bind['sh_addr']
    bind_size  = bind['sh_size']

    if (entrypoint - bind_addr) > bind_size or (entrypoint - bind_addr) < 0:
        log.error("entrypoint is not in bind section, don't know what to do")
        exit(-1)

    bind_entry = entrypoint - bind_addr

    data = bind.data()
    log.debug(dump_hex(data[bind_entry:]))

    header_offset = bind_entry - 0xd0
    log.info("decoding header at 0x{:x}".format(header_offset))

    key = xor_key = int.from_bytes(data[header_offset:header_offset+4], byteorder='little')

    header = bytes()

    log.debug("found xor key 0x{:x}".format(key))

    header = bytearray()

    while header_offset < bind_entry:
        header_offset += 4
        val = int.from_bytes(data[header_offset:header_offset+4], byteorder='little')
        header.extend(int.to_bytes(val ^ key, 4, byteorder='little'))
        
        key = val



    log.debug("decoded header {}".format(dump_hex(header)))

    names = """
            signature base drm_entrypoint bind_offset u0 \
            real_entrypoint u1 payload_size u2 u3 appid  \
            flags bind_virtual_size u4 code_virtual_addr \
            code_size aes_key aes_iv code_stolen keys u5 \
            u6 u7
            """
    
    SteamStubHeader = namedtuple('SteamStubHeader', names)

    pattern = "<IQQIIQIIIIIIIIQQ32s16s16s16s32sQI"


    h = SteamStubHeader._make(struct.unpack(pattern, header))
    log.info("signature 0x{:x}".format(h.signature))
    log.info("base 0x{:x}".format(h.base))
    log.info("drm_entrypoint 0x{:x}".format(h.drm_entrypoint))
    log.info("bind_offset 0x{:x}".format(h.bind_offset))
    log.debug("u0 0x{:x}".format(h.u0))
    log.info("real_entrypoint 0x{:x}".format(h.real_entrypoint))
    log.debug("u1 0x{:x}".format(h.u1))
    log.info("payload_size 0x{:x}".format(h.payload_size))
    log.debug("u2 0x{:x}".format(h.u2))
    log.debug("u3 0x{:x}".format(h.u3))
    log.info("appid {:}".format(h.appid))
    log.info("flags {:x}".format(h.flags))
    log.info("bind_virtual_size 0x{:x}".format(h.bind_virtual_size))
    log.debug("u4 0x{:x}".format(h.u4))
    log.info("code_virtual_addr 0x{:x}".format(h.code_virtual_addr))
    log.info("code_size 0x{:x}".format(h.code_size))
    log.info("aes_key 0x{:}".format(dump_hex(h.aes_key)))
    log.info("aes_iv 0x{:}".format(dump_hex(h.aes_iv)))
    log.debug("code_stolen 0x{:}".format(dump_hex(h.code_stolen)))
    log.debug("keys 0x{:}".format(dump_hex(h.keys)))
    log.debug("u5 0x{:}".format(dump_hex(h.u5)))
    log.debug("u6 0x{:x}".format(h.u6))
    log.debug("u7 0x{:x}".format(h.u7))

    if h.signature != 0xc0dec0df:
        log.error("invalid signature {} != 0xc0dec0df".format(h.signature))
        exit(-1)

    log.info("searching for section with code")

    code_section = None
    code_section_offset = None

    for s in e.iter_sections():
        if s.header['sh_offset'] <= h.code_virtual_addr:
            if (s.header['sh_offset'] + s.header['sh_size']) > h.code_virtual_addr:
                code_section = s
                code_section_offset = s.header['sh_offset']

    if code_section is None:
        log.error("could not find section for offset 0x{:x}".format(h.code_virtual_addr))
    else:
        log.info("found section containing encrypted code: {}".format(code_section.name))


    log.info("reading encrypted code")
    code_data = bytearray(h.code_stolen)
    code_data.extend(code_section.data()[code_section_offset - h.code_virtual_addr:h.code_size])

    log.info("decrypting code")
    cipher = AES.new(h.aes_key, AES.MODE_ECB)
    new_iv = cipher.decrypt(h.aes_iv)

    cipher = AES.new(h.aes_key, AES.MODE_CBC, new_iv)
    code_unencrypted = cipher.decrypt(code_data)


    f.seek(0, 0)
    binary_unpacked = binary + ".unpacked"

    log.info("writing unpacked binary to {}".format(binary_unpacked))

    real_entrypoint = h.real_entrypoint - code_section_offset + code_section.header["sh_addr"]
    log.info("real entrypoint 0x{:x}".format(real_entrypoint))

    with open(binary_unpacked, "wb") as outfile:
        outfile.write(f.read())
        outfile.seek(code_section_offset, 0)
        log.info("writing decrypted code")
        outfile.write(code_unencrypted[:code_section.header["sh_size"] & 0xfffffffffffffff0])
        outfile.seek(0x18, 0)
        log.info("patching entrypoint")
        outfile.write(int.to_bytes(real_entrypoint, 8, byteorder='little'))

    os.chmod(binary_unpacked, 0o755)

    log.info("done, have fun :)")
    
