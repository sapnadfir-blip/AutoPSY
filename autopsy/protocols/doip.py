"""
DoIP (Diagnostics over IP) and UDS (Unified Diagnostic Services) protocol implementation.

Reused and extended from SOMEIPwn with forensic-specific UDS commands:
  - ReadDTCInformation (0x19) — extract all diagnostic trouble codes
  - ReadMemoryByAddress (0x23) — read ECU firmware for hash comparison
  - SecurityAccess (0x27) — detect unauthorized unlock attempts
  - RequestDownload (0x34) — detect firmware reflash evidence
"""
import struct
import socket
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import IntEnum


DOIP_PORT = 13400
DOIP_PROTOCOL_VERSION = 0x02
DOIP_INVERSE_VERSION = 0xFD


class DoIPPayloadType(IntEnum):
    VEHICLE_ID_REQUEST = 0x0001
    VEHICLE_ID_REQUEST_EID = 0x0002
    VEHICLE_ID_REQUEST_VIN = 0x0003
    VEHICLE_ID_RESPONSE = 0x0004
    ROUTING_ACTIVATION_REQUEST = 0x0005
    ROUTING_ACTIVATION_RESPONSE = 0x0006
    ALIVE_CHECK_REQUEST = 0x0007
    ALIVE_CHECK_RESPONSE = 0x0008
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_MESSAGE_ACK = 0x8002
    DIAGNOSTIC_MESSAGE_NACK = 0x8003
    ENTITY_STATUS_REQUEST = 0x4001
    ENTITY_STATUS_RESPONSE = 0x4002
    POWER_MODE_INFO_REQUEST = 0x4003
    POWER_MODE_INFO_RESPONSE = 0x4004
    GENERIC_NACK = 0x0000


class UDSServiceID(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    CLEAR_DTC = 0x14
    READ_DTC = 0x19
    READ_DATA_BY_ID = 0x22
    READ_MEMORY_BY_ADDRESS = 0x23
    SECURITY_ACCESS = 0x27
    COMMUNICATION_CONTROL = 0x28
    WRITE_DATA_BY_ID = 0x2E
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    REQUEST_UPLOAD = 0x35
    TRANSFER_DATA = 0x36
    TRANSFER_EXIT = 0x37
    WRITE_MEMORY_BY_ADDRESS = 0x3D
    TESTER_PRESENT = 0x3E
    INPUT_OUTPUT_CONTROL = 0x2F


class DTCStatusMask(IntEnum):
    TEST_FAILED = 0x01
    TEST_FAILED_THIS_CYCLE = 0x02
    PENDING = 0x04
    CONFIRMED = 0x08
    TEST_NOT_COMPLETE_SINCE_CLEAR = 0x10
    TEST_FAILED_SINCE_CLEAR = 0x20
    TEST_NOT_COMPLETE_THIS_CYCLE = 0x40
    WARNING_INDICATOR = 0x80
    ALL = 0xFF


class DiagnosticSession(IntEnum):
    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED = 0x03


class NRC(IntEnum):
    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_LENGTH = 0x13
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    INVALID_KEY = 0x35
    EXCEEDED_ATTEMPTS = 0x36
    TIME_DELAY_NOT_EXPIRED = 0x37
    UPLOAD_DOWNLOAD_NOT_ACCEPTED = 0x70
    TRANSFER_SUSPENDED = 0x71
    GENERAL_PROGRAMMING_FAILURE = 0x72
    RESPONSE_PENDING = 0x78


COMMON_DIDS = {
    0xF186: "Active Diagnostic Session",
    0xF187: "Spare Part Number",
    0xF188: "ECU Software Number",
    0xF189: "ECU Software Version",
    0xF18A: "System Supplier ID",
    0xF18B: "ECU Manufacturing Date",
    0xF18C: "ECU Serial Number",
    0xF190: "VIN",
    0xF191: "ECU Hardware Number",
    0xF192: "Supplier Hardware Number",
    0xF193: "Supplier Hardware Version",
    0xF194: "Supplier Software Number",
    0xF195: "Supplier Software Version",
    0xF197: "System Name / Engine Type",
    0xF19E: "ASAM/ODX File ID",
    0xF1A0: "Boot Software ID",
}

FORENSIC_DIDS = {
    0xF186: "Active Session (was ECU in programming mode?)",
    0xF18B: "Manufacturing Date (verify ECU authenticity)",
    0xF18C: "Serial Number (match to vehicle records)",
    0xF188: "Software Number (detect reflash)",
    0xF189: "Software Version (detect OTA changes)",
    0xF191: "Hardware Number (detect ECU swap)",
    0xF1A0: "Boot Software (detect bootloader tampering)",
}


@dataclass
class DoIPHeader:
    payload_type: DoIPPayloadType
    payload: bytes = b""


def build_doip_header(hdr: DoIPHeader) -> bytes:
    buf = struct.pack(">BB", DOIP_PROTOCOL_VERSION, DOIP_INVERSE_VERSION)
    buf += struct.pack(">H", hdr.payload_type)
    buf += struct.pack(">I", len(hdr.payload))
    buf += hdr.payload
    return buf


def build_vehicle_id_request() -> bytes:
    return build_doip_header(DoIPHeader(DoIPPayloadType.VEHICLE_ID_REQUEST))


def build_vehicle_id_request_vin(vin: str) -> bytes:
    return build_doip_header(DoIPHeader(
        DoIPPayloadType.VEHICLE_ID_REQUEST_VIN,
        vin.encode("ascii")[:17].ljust(17, b"\x00"),
    ))


def build_routing_activation(source_address: int = 0x0E80,
                             activation_type: int = 0x00) -> bytes:
    payload = struct.pack(">H", source_address)
    payload += struct.pack(">B", activation_type)
    payload += b"\x00\x00\x00\x00"
    return build_doip_header(DoIPHeader(DoIPPayloadType.ROUTING_ACTIVATION_REQUEST, payload))


def build_diagnostic_message(source_address: int, target_address: int,
                             uds_data: bytes) -> bytes:
    payload = struct.pack(">H", source_address)
    payload += struct.pack(">H", target_address)
    payload += uds_data
    return build_doip_header(DoIPHeader(DoIPPayloadType.DIAGNOSTIC_MESSAGE, payload))


def build_uds_session_control(session_type: int = DiagnosticSession.DEFAULT) -> bytes:
    return bytes([UDSServiceID.DIAGNOSTIC_SESSION_CONTROL, session_type])


def build_uds_extended_session() -> bytes:
    return build_uds_session_control(DiagnosticSession.EXTENDED)


def build_uds_programming_session() -> bytes:
    return build_uds_session_control(DiagnosticSession.PROGRAMMING)


def build_uds_security_access(sub_function: int = 0x01, seed_key: bytes = b"") -> bytes:
    data = bytes([UDSServiceID.SECURITY_ACCESS, sub_function])
    if seed_key:
        data += seed_key
    return data


def build_uds_read_data(did: int) -> bytes:
    return struct.pack(">BH", UDSServiceID.READ_DATA_BY_ID, did)


def build_uds_read_multi_data(dids: List[int]) -> bytes:
    buf = bytes([UDSServiceID.READ_DATA_BY_ID])
    for did in dids:
        buf += struct.pack(">H", did)
    return buf


def build_uds_write_data(did: int, data: bytes) -> bytes:
    return struct.pack(">BH", UDSServiceID.WRITE_DATA_BY_ID, did) + data


def build_uds_read_memory(address: int, size: int, addr_len: int = 4,
                          size_len: int = 2) -> bytes:
    addr_and_size = (size_len << 4) | addr_len
    buf = bytes([UDSServiceID.READ_MEMORY_BY_ADDRESS, addr_and_size])
    buf += address.to_bytes(addr_len, "big")
    buf += size.to_bytes(size_len, "big")
    return buf


def build_uds_ecu_reset(reset_type: int = 0x01) -> bytes:
    return bytes([UDSServiceID.ECU_RESET, reset_type])


def build_uds_tester_present() -> bytes:
    return bytes([UDSServiceID.TESTER_PRESENT, 0x00])


def build_uds_clear_dtc(group: int = 0xFFFFFF) -> bytes:
    buf = bytes([UDSServiceID.CLEAR_DTC])
    buf += group.to_bytes(3, "big")
    return buf


def build_uds_read_dtc(sub_function: int = 0x02, status_mask: int = DTCStatusMask.ALL) -> bytes:
    return bytes([UDSServiceID.READ_DTC, sub_function, status_mask])


def build_uds_read_dtc_by_status(status_mask: int = DTCStatusMask.ALL) -> bytes:
    return build_uds_read_dtc(0x02, status_mask)


def build_uds_read_supported_dtc() -> bytes:
    return build_uds_read_dtc(0x0A, 0x00)


def build_uds_read_dtc_snapshot(dtc: int, record_number: int = 0xFF) -> bytes:
    buf = bytes([UDSServiceID.READ_DTC, 0x04])
    buf += dtc.to_bytes(3, "big")
    buf += bytes([record_number])
    return buf


def build_uds_read_dtc_extended(dtc: int, record_number: int = 0xFF) -> bytes:
    buf = bytes([UDSServiceID.READ_DTC, 0x06])
    buf += dtc.to_bytes(3, "big")
    buf += bytes([record_number])
    return buf


def build_uds_request_download(address: int, size: int, compression: int = 0,
                               encrypting: int = 0) -> bytes:
    data_format = (compression << 4) | encrypting
    buf = bytes([UDSServiceID.REQUEST_DOWNLOAD, data_format])
    addr_and_size = (4 << 4) | 4
    buf += bytes([addr_and_size])
    buf += address.to_bytes(4, "big")
    buf += size.to_bytes(4, "big")
    return buf


def build_uds_routine_control(routine_id: int, sub_function: int = 0x01,
                              data: bytes = b"") -> bytes:
    buf = struct.pack(">BBH", UDSServiceID.ROUTINE_CONTROL, sub_function, routine_id)
    buf += data
    return buf


def parse_doip_header(data: bytes) -> Optional[dict]:
    if len(data) < 8:
        return None
    ver, inv_ver = struct.unpack(">BB", data[0:2])
    payload_type = struct.unpack(">H", data[2:4])[0]
    payload_len = struct.unpack(">I", data[4:8])[0]

    result = {
        "version": ver,
        "payload_type": payload_type,
        "payload_length": payload_len,
        "payload": data[8:8 + payload_len] if payload_len <= len(data) - 8 else data[8:],
    }

    if payload_type == DoIPPayloadType.VEHICLE_ID_RESPONSE and len(result["payload"]) >= 33:
        p = result["payload"]
        result["vin"] = p[0:17].decode("ascii", errors="replace")
        result["logical_address"] = struct.unpack(">H", p[17:19])[0]
        result["eid"] = p[19:25].hex(":")
        result["gid"] = p[25:31].hex(":")
        result["further_action"] = p[31]
        if len(p) > 32:
            result["sync_status"] = p[32]

    return result


def parse_uds_response(data: bytes) -> Optional[dict]:
    if not data:
        return None
    sid = data[0]
    if sid == 0x7F:
        return {
            "type": "negative",
            "service": data[1] if len(data) > 1 else 0,
            "nrc": data[2] if len(data) > 2 else 0,
            "nrc_name": NRC(data[2]).name if len(data) > 2 and data[2] in NRC._value2member_map_ else "UNKNOWN",
        }
    return {
        "type": "positive",
        "service": sid - 0x40,
        "data": data[1:],
    }
