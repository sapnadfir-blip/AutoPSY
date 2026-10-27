"""
SOME/IP protocol implementation for automotive Ethernet forensics.

SOME/IP is the inter-ECU communication protocol on automotive Ethernet.
No authentication, no encryption, no integrity.
"""
import struct
import socket
from dataclasses import dataclass
from typing import List, Optional
from enum import IntEnum


SOMEIP_SD_PORT = 30490
SOMEIP_SD_MULTICAST = "224.224.224.245"
SOMEIP_SD_SERVICE_ID = 0xFFFF
SOMEIP_SD_METHOD_ID = 0x8100


class MessageType(IntEnum):
    REQUEST = 0x00
    REQUEST_NO_RETURN = 0x01
    NOTIFICATION = 0x02
    RESPONSE = 0x80
    ERROR = 0x81
    TP_REQUEST = 0x20
    TP_RESPONSE = 0xA0


class ReturnCode(IntEnum):
    E_OK = 0x00
    E_NOT_OK = 0x01
    E_UNKNOWN_SERVICE = 0x02
    E_UNKNOWN_METHOD = 0x03
    E_NOT_READY = 0x04
    E_TIMEOUT = 0x06
    E_MALFORMED_MESSAGE = 0x09


class SDEntryType(IntEnum):
    FIND_SERVICE = 0x00
    OFFER_SERVICE = 0x01
    SUBSCRIBE_EVENTGROUP = 0x06
    SUBSCRIBE_EVENTGROUP_ACK = 0x07


@dataclass
class SOMEIPHeader:
    service_id: int = 0x0000
    method_id: int = 0x0000
    client_id: int = 0x0001
    session_id: int = 0x0001
    protocol_version: int = 0x01
    interface_version: int = 0x01
    message_type: MessageType = MessageType.REQUEST
    return_code: ReturnCode = ReturnCode.E_OK
    payload: bytes = b""


@dataclass
class SDEntry:
    entry_type: SDEntryType = SDEntryType.FIND_SERVICE
    service_id: int = 0xFFFF
    instance_id: int = 0xFFFF
    major_version: int = 0xFF
    ttl: int = 3
    minor_version: int = 0xFFFFFFFF
    eventgroup_id: int = 0x0000


@dataclass
class SDOption:
    option_type: int = 0x04
    protocol: int = 0x11
    ip_address: str = "0.0.0.0"
    port: int = 0


def build_someip_header(hdr: SOMEIPHeader) -> bytes:
    message_id = (hdr.service_id << 16) | hdr.method_id
    length = len(hdr.payload) + 8
    request_id = (hdr.client_id << 16) | hdr.session_id
    buf = struct.pack(">I", message_id)
    buf += struct.pack(">I", length)
    buf += struct.pack(">I", request_id)
    buf += struct.pack(">BBBB", hdr.protocol_version, hdr.interface_version,
                       hdr.message_type, hdr.return_code)
    buf += hdr.payload
    return buf


def build_sd_entry(entry: SDEntry) -> bytes:
    buf = struct.pack(">B", entry.entry_type)
    buf += struct.pack(">B", 0)
    buf += struct.pack(">BB", 0, 0)
    buf += struct.pack(">H", entry.service_id)
    buf += struct.pack(">H", entry.instance_id)
    buf += struct.pack(">B", entry.major_version)
    ttl_bytes = struct.pack(">I", entry.ttl)
    buf += ttl_bytes[1:]
    if entry.entry_type in (SDEntryType.FIND_SERVICE, SDEntryType.OFFER_SERVICE):
        buf += struct.pack(">I", entry.minor_version)
    else:
        buf += struct.pack(">B", 0)
        buf += struct.pack(">B", 0)
        buf += struct.pack(">H", entry.eventgroup_id)
    return buf


def build_sd_option_ipv4(opt: SDOption) -> bytes:
    buf = struct.pack(">H", 9)
    buf += struct.pack(">B", 0x04)
    buf += struct.pack(">B", 0)
    buf += socket.inet_aton(opt.ip_address)
    buf += struct.pack(">B", 0)
    buf += struct.pack(">B", opt.protocol)
    buf += struct.pack(">H", opt.port)
    return buf


def build_sd_message(entries: List[SDEntry], options: List[SDOption] = None) -> bytes:
    entries_data = b"".join(build_sd_entry(e) for e in entries)
    options_data = b"".join(build_sd_option_ipv4(o) for o in (options or []))
    payload = struct.pack(">B", 0xC0) + b"\x00\x00\x00"
    payload += struct.pack(">I", len(entries_data)) + entries_data
    payload += struct.pack(">I", len(options_data)) + options_data
    hdr = SOMEIPHeader(
        service_id=SOMEIP_SD_SERVICE_ID, method_id=SOMEIP_SD_METHOD_ID,
        client_id=0x0000, session_id=0x0001,
        message_type=MessageType.NOTIFICATION, payload=payload,
    )
    return build_someip_header(hdr)


def parse_someip_header(data: bytes) -> Optional[SOMEIPHeader]:
    if len(data) < 16:
        return None
    message_id = struct.unpack(">I", data[0:4])[0]
    length = struct.unpack(">I", data[4:8])[0]
    request_id = struct.unpack(">I", data[8:12])[0]
    proto_ver, iface_ver, msg_type, ret_code = struct.unpack(">BBBB", data[12:16])
    return SOMEIPHeader(
        service_id=(message_id >> 16) & 0xFFFF,
        method_id=message_id & 0xFFFF,
        client_id=(request_id >> 16) & 0xFFFF,
        session_id=request_id & 0xFFFF,
        protocol_version=proto_ver, interface_version=iface_ver,
        message_type=msg_type, return_code=ret_code,
        payload=data[16:8 + length] if length > 8 else b"",
    )
