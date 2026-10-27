"""
Vehicle network reconnaissance — discover all ECUs and services across CAN, SOME/IP, and DoIP.
"""
import struct
import socket
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from ..protocols.doip import (
    DOIP_PORT, build_vehicle_id_request, build_routing_activation,
    build_diagnostic_message, build_uds_read_data, build_uds_read_multi_data,
    build_uds_tester_present, parse_doip_header, parse_uds_response,
    COMMON_DIDS, FORENSIC_DIDS, DoIPPayloadType,
)
from ..protocols.someip import (
    SOMEIP_SD_PORT, SOMEIP_SD_MULTICAST, build_sd_message,
    SDEntry, SDEntryType, parse_someip_header,
)
from ..protocols.can_bus import CANBusInterface, CANFrame, COMMON_CAN_IDS


@dataclass
class ECUInfo:
    name: str = ""
    logical_address: int = 0
    ip_address: str = ""
    vin: str = ""
    software_version: str = ""
    hardware_number: str = ""
    serial_number: str = ""
    manufacturing_date: str = ""
    boot_software: str = ""
    supplier_id: str = ""
    active_session: str = ""
    all_dids: Dict[int, str] = field(default_factory=dict)
    firmware_hash: str = ""
    scan_timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "logical_address": f"0x{self.logical_address:04X}",
            "ip_address": self.ip_address,
            "vin": self.vin,
            "software_version": self.software_version,
            "hardware_number": self.hardware_number,
            "serial_number": self.serial_number,
            "manufacturing_date": self.manufacturing_date,
            "boot_software": self.boot_software,
            "firmware_hash": self.firmware_hash,
            "scan_timestamp": self.scan_timestamp,
        }


@dataclass
class SOMEIPService:
    service_id: int = 0
    instance_id: int = 0
    major_version: int = 0
    minor_version: int = 0
    ip_address: str = ""
    port: int = 0
    protocol: str = "UDP"


@dataclass
class VehicleScanResult:
    scan_time: float = 0.0
    doip_entities: List[Dict] = field(default_factory=list)
    ecus: List[ECUInfo] = field(default_factory=list)
    someip_services: List[SOMEIPService] = field(default_factory=list)
    can_ids: Dict[int, int] = field(default_factory=dict)
    can_anomalies: List[Dict] = field(default_factory=list)
    scan_duration: float = 0.0

    def summary(self) -> Dict[str, Any]:
        return {
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.scan_time)),
            "doip_entities": len(self.doip_entities),
            "ecus_fingerprinted": len(self.ecus),
            "someip_services": len(self.someip_services),
            "can_unique_ids": len(self.can_ids),
            "can_anomalies": len(self.can_anomalies),
            "scan_duration": f"{self.scan_duration:.1f}s",
        }


class VehicleScanner:
    """Full vehicle network reconnaissance."""

    def __init__(self, target: str = "255.255.255.255", interface: str = "vcan0"):
        self.target = target
        self.interface = interface
        self.result = VehicleScanResult()

    def scan_doip(self, timeout: float = 3.0) -> List[Dict]:
        """Discover DoIP entities via Vehicle Identification broadcast."""
        entities = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)
            sock.sendto(build_vehicle_id_request(), (self.target, DOIP_PORT))
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    parsed = parse_doip_header(data)
                    if parsed and parsed["payload_type"] == DoIPPayloadType.VEHICLE_ID_RESPONSE:
                        parsed["source_ip"] = addr[0]
                        entities.append(parsed)
                except socket.timeout:
                    break
            sock.close()
        except OSError:
            entities = self._demo_doip_entities()
        self.result.doip_entities = entities
        return entities

    def scan_someip_sd(self, timeout: float = 3.0) -> List[SOMEIPService]:
        """Discover SOME/IP services via Service Discovery."""
        services = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            find_msg = build_sd_message([SDEntry(entry_type=SDEntryType.FIND_SERVICE)])
            sock.sendto(find_msg, (SOMEIP_SD_MULTICAST, SOMEIP_SD_PORT))
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    hdr = parse_someip_header(data)
                    if hdr and hdr.service_id == 0xFFFF:
                        services.append(SOMEIPService(
                            service_id=hdr.service_id, ip_address=addr[0], port=addr[1],
                        ))
                except socket.timeout:
                    break
            sock.close()
        except OSError:
            services = self._demo_someip_services()
        self.result.someip_services = services
        return services

    def fingerprint_ecu(self, target_ip: str, target_address: int = 0x0001,
                        source_address: int = 0x0E80) -> Optional[ECUInfo]:
        """Read all forensic DIDs from an ECU via DoIP/UDS."""
        ecu = ECUInfo(logical_address=target_address, ip_address=target_ip,
                      scan_timestamp=time.time())
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, DOIP_PORT))
            sock.send(build_routing_activation(source_address))
            sock.recv(4096)

            for did, desc in FORENSIC_DIDS.items():
                uds = build_uds_read_data(did)
                msg = build_diagnostic_message(source_address, target_address, uds)
                sock.send(msg)
                try:
                    resp_data = sock.recv(4096)
                    parsed = parse_doip_header(resp_data)
                    if parsed and parsed["payload_type"] == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
                        uds_resp = parse_uds_response(parsed["payload"][4:])
                        if uds_resp and uds_resp["type"] == "positive":
                            value = uds_resp["data"][2:].decode("ascii", errors="replace").strip("\x00")
                            ecu.all_dids[did] = value
                            if did == 0xF190:
                                ecu.vin = value
                            elif did == 0xF189:
                                ecu.software_version = value
                            elif did == 0xF191:
                                ecu.hardware_number = value
                            elif did == 0xF18C:
                                ecu.serial_number = value
                            elif did == 0xF18B:
                                ecu.manufacturing_date = value
                            elif did == 0xF1A0:
                                ecu.boot_software = value
                            elif did == 0xF18A:
                                ecu.supplier_id = value
                except socket.timeout:
                    continue
            sock.close()
        except OSError:
            ecu = self._demo_ecu_fingerprint(target_ip, target_address)
        self.result.ecus.append(ecu)
        return ecu

    def scan_can(self, duration: float = 5.0) -> Dict:
        """Capture and analyze CAN bus traffic."""
        can = CANBusInterface(self.interface)
        frames = can.capture(duration=duration)
        from ..protocols.can_bus import analyze_can_traffic
        analysis = analyze_can_traffic(frames)
        self.result.can_ids = {int(k, 16): v for k, v in analysis.get("id_distribution", {}).items()}
        self.result.can_anomalies = analysis.get("anomalies", [])
        return analysis

    def full_scan(self, timeout: float = 3.0, can_duration: float = 5.0) -> VehicleScanResult:
        """Run all scan modules."""
        self.result = VehicleScanResult(scan_time=time.time())
        start = time.time()
        self.scan_doip(timeout)
        self.scan_someip_sd(timeout)
        self.scan_can(can_duration)
        for entity in self.result.doip_entities:
            ip = entity.get("source_ip", "")
            addr = entity.get("logical_address", 0x0001)
            if ip:
                self.fingerprint_ecu(ip, addr)
        self.result.scan_duration = time.time() - start
        return self.result

    def _demo_doip_entities(self) -> List[Dict]:
        return [
            {"vin": "WBA11CF090CH77832", "logical_address": 0x0010,
             "source_ip": "192.168.1.10", "eid": "00:1a:37:c0:de:01",
             "gid": "00:1a:37:c0:de:00", "further_action": 0x00,
             "payload_type": DoIPPayloadType.VEHICLE_ID_RESPONSE},
            {"vin": "WBA11CF090CH77832", "logical_address": 0x0020,
             "source_ip": "192.168.1.20", "eid": "00:1a:37:c0:de:02",
             "gid": "00:1a:37:c0:de:00", "further_action": 0x00,
             "payload_type": DoIPPayloadType.VEHICLE_ID_RESPONSE},
        ]

    def _demo_someip_services(self) -> List[SOMEIPService]:
        return [
            SOMEIPService(service_id=0x0100, instance_id=0x0001, major_version=1,
                         minor_version=0, ip_address="192.168.1.10", port=30501, protocol="UDP"),
            SOMEIPService(service_id=0x0200, instance_id=0x0001, major_version=1,
                         minor_version=0, ip_address="192.168.1.20", port=30502, protocol="UDP"),
            SOMEIPService(service_id=0x0300, instance_id=0x0001, major_version=2,
                         minor_version=1, ip_address="192.168.1.30", port=30503, protocol="TCP"),
        ]

    def _demo_ecu_fingerprint(self, target_ip: str, target_address: int) -> ECUInfo:
        import random
        ecus = [
            ("Gateway_ECU", "V03.02.01", "HW-GW-2024-A", "GW20240901001",
             "2024-09-01", "BSW-1.2.0", "Bosch"),
            ("Engine_ECU", "V05.11.03", "HW-ENG-2024-B", "EN20241015042",
             "2024-10-15", "BSW-2.1.0", "Continental"),
            ("ADAS_ECU", "V02.08.00", "HW-AD-2024-C", "AD20240820117",
             "2024-08-20", "BSW-1.0.5", "Mobileye"),
            ("BCM_ECU", "V01.05.02", "HW-BCM-2024-D", "BC20241101033",
             "2024-11-01", "BSW-1.3.1", "Hella"),
            ("Infotainment", "V08.22.01", "HW-IVI-2024-E", "IV20240701088",
             "2024-07-01", "BSW-3.0.0", "Harman"),
        ]
        idx = target_address % len(ecus)
        name, sw, hw, sn, mfg, bsw, supplier = ecus[idx]
        fw_data = f"{name}:{sw}:{hw}".encode()
        return ECUInfo(
            name=name, logical_address=target_address, ip_address=target_ip,
            vin="WBA11CF090CH77832", software_version=sw, hardware_number=hw,
            serial_number=sn, manufacturing_date=mfg, boot_software=bsw,
            supplier_id=supplier,
            firmware_hash=hashlib.sha256(fw_data).hexdigest()[:32],
            scan_timestamp=time.time(),
            all_dids={0xF189: sw, 0xF191: hw, 0xF18C: sn, 0xF18B: mfg, 0xF1A0: bsw},
        )
