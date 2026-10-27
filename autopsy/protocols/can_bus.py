"""
CAN bus protocol implementation for forensic acquisition and attack simulation.

CAN (Controller Area Network) is the primary in-vehicle network.
No source authentication — any node can send any message ID.
No encryption — all traffic is broadcast and readable by every node.

Standard CAN Frame:
  Arbitration ID (11 bits standard / 29 bits extended)
  DLC (4 bits) — data length code (0-8 bytes)
  Data (0-8 bytes)

CAN-FD extends data to 64 bytes with flexible data rate.
"""
import struct
import time
import hashlib
import socket
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from enum import IntEnum


class CANFrameType(IntEnum):
    DATA = 0
    REMOTE = 1
    ERROR = 2
    OVERLOAD = 3


@dataclass
class CANFrame:
    arb_id: int = 0
    data: bytes = b""
    dlc: int = 0
    is_extended: bool = False
    is_fd: bool = False
    is_remote: bool = False
    timestamp: float = 0.0
    channel: str = ""

    def __post_init__(self):
        if self.dlc == 0 and self.data:
            self.dlc = len(self.data)
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_bytes(self) -> bytes:
        flags = 0
        if self.is_extended:
            flags |= 0x01
        if self.is_fd:
            flags |= 0x02
        if self.is_remote:
            flags |= 0x04
        buf = struct.pack("<IBI", self.arb_id, flags, self.dlc)
        buf += self.data[:self.dlc].ljust(self.dlc, b"\x00")
        buf += struct.pack("<d", self.timestamp)
        return buf

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["CANFrame"]:
        if len(data) < 13:
            return None
        arb_id, flags, dlc = struct.unpack("<IBI", data[0:9])
        payload = data[9:9 + dlc]
        ts = struct.unpack("<d", data[9 + dlc:17 + dlc])[0] if len(data) >= 17 + dlc else time.time()
        return cls(
            arb_id=arb_id, data=payload, dlc=dlc,
            is_extended=bool(flags & 0x01), is_fd=bool(flags & 0x02),
            is_remote=bool(flags & 0x04), timestamp=ts,
        )

    def hex_dump(self) -> str:
        id_str = f"{self.arb_id:08X}" if self.is_extended else f"{self.arb_id:03X}"
        data_str = " ".join(f"{b:02X}" for b in self.data[:self.dlc])
        return f"[{self.timestamp:.6f}] {id_str} [{self.dlc}] {data_str}"


# Well-known CAN message IDs (OBD-II standard PIDs)
OBD2_REQUEST_ID = 0x7DF
OBD2_RESPONSE_BASE = 0x7E8

# Common CAN IDs by function (vary by manufacturer)
COMMON_CAN_IDS = {
    0x000: "Network Management",
    0x100: "Engine Control",
    0x180: "Transmission Control",
    0x200: "ABS / ESP",
    0x280: "Airbag / SRS",
    0x300: "Instrument Cluster",
    0x380: "Body Control Module",
    0x400: "Climate Control",
    0x480: "Infotainment",
    0x500: "Steering",
    0x600: "Gateway",
    0x7DF: "OBD-II Diagnostic Request",
    0x7E0: "ECU Diagnostic Request (Physical)",
    0x7E8: "ECU Diagnostic Response",
}


class CANBusInterface:
    """CAN bus operations — capture, inject, analyze."""

    def __init__(self, interface: str = "vcan0"):
        self.interface = interface
        self.captured_frames: List[CANFrame] = []
        self._sock = None

    def _create_socket(self) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            sock.bind((self.interface,))
            sock.settimeout(1.0)
            return sock
        except (OSError, AttributeError):
            return None

    def capture(self, duration: float = 5.0, max_frames: int = 10000) -> List[CANFrame]:
        self.captured_frames = []
        sock = self._create_socket()
        if not sock:
            return self._generate_demo_capture(duration, max_frames)
        start = time.time()
        try:
            while time.time() - start < duration and len(self.captured_frames) < max_frames:
                try:
                    raw = sock.recv(72)
                    arb_id, dlc = struct.unpack("<IB", raw[0:5])
                    data = raw[8:8 + dlc]
                    frame = CANFrame(
                        arb_id=arb_id & 0x1FFFFFFF, data=data, dlc=dlc,
                        is_extended=bool(arb_id & 0x80000000),
                        timestamp=time.time(), channel=self.interface,
                    )
                    self.captured_frames.append(frame)
                except socket.timeout:
                    continue
        finally:
            sock.close()
        return self.captured_frames

    def inject(self, frame: CANFrame) -> bool:
        sock = self._create_socket()
        if not sock:
            return False
        try:
            can_pkt = struct.pack("<I", frame.arb_id)
            can_pkt += struct.pack("<B", frame.dlc)
            can_pkt += b"\x00\x00\x00"
            can_pkt += frame.data[:8].ljust(8, b"\x00")
            sock.send(can_pkt)
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _generate_demo_capture(self, duration: float, max_frames: int) -> List[CANFrame]:
        """Generate realistic CAN bus traffic for demo/testing."""
        import random
        frames = []
        t = time.time()
        ecu_patterns = [
            (0x0C0, 8, 0.010, "Engine RPM + Speed"),
            (0x0D0, 8, 0.010, "Throttle + Brake"),
            (0x1A0, 8, 0.020, "Wheel Speeds"),
            (0x1B0, 4, 0.020, "Steering Angle"),
            (0x280, 8, 0.100, "SRS Status"),
            (0x320, 8, 0.050, "Gear + Transmission"),
            (0x3B0, 8, 0.100, "Door Status"),
            (0x420, 6, 0.200, "Climate Control"),
            (0x520, 8, 0.050, "Parking Sensors"),
            (0x620, 8, 0.500, "Gateway Heartbeat"),
        ]
        count = 0
        while count < min(max_frames, int(duration / 0.001)):
            for arb_id, dlc, interval, _ in ecu_patterns:
                jitter = random.uniform(-0.001, 0.001)
                frame_time = t + count * 0.001 + jitter
                data = bytes(random.randint(0, 255) for _ in range(dlc))
                frames.append(CANFrame(
                    arb_id=arb_id, data=data, dlc=dlc,
                    timestamp=frame_time, channel=self.interface,
                ))
                count += 1
                if count >= min(max_frames, int(duration / 0.001)):
                    break
        frames.sort(key=lambda f: f.timestamp)
        self.captured_frames = frames
        return frames


def analyze_can_traffic(frames: List[CANFrame]) -> Dict:
    """Analyze captured CAN traffic for forensic indicators."""
    if not frames:
        return {"total_frames": 0, "unique_ids": 0, "duration": 0}

    id_counts: Dict[int, int] = {}
    id_intervals: Dict[int, List[float]] = {}
    id_first_seen: Dict[int, float] = {}
    id_last_seen: Dict[int, float] = {}

    for frame in frames:
        aid = frame.arb_id
        id_counts[aid] = id_counts.get(aid, 0) + 1
        if aid not in id_first_seen:
            id_first_seen[aid] = frame.timestamp
            id_intervals[aid] = []
        else:
            id_intervals[aid].append(frame.timestamp - id_last_seen[aid])
        id_last_seen[aid] = frame.timestamp

    duration = frames[-1].timestamp - frames[0].timestamp if len(frames) > 1 else 0

    # Detect anomalies
    anomalies = []

    for aid, intervals in id_intervals.items():
        if len(intervals) < 5:
            continue
        avg = sum(intervals) / len(intervals)
        if avg > 0:
            jitter_vals = [abs(i - avg) / avg for i in intervals]
            max_jitter = max(jitter_vals) if jitter_vals else 0
            if max_jitter > 5.0:
                anomalies.append({
                    "type": "timing_anomaly",
                    "arb_id": f"0x{aid:03X}",
                    "detail": f"Timing jitter {max_jitter:.1f}x normal — possible injection",
                    "severity": "HIGH",
                })

    # Check for unusual IDs (not in common list)
    for aid in id_counts:
        if aid not in COMMON_CAN_IDS and aid < 0x700:
            if id_counts[aid] < 3:
                anomalies.append({
                    "type": "unknown_id",
                    "arb_id": f"0x{aid:03X}",
                    "detail": f"Rare message ID seen {id_counts[aid]} times — possible probe",
                    "severity": "MEDIUM",
                })

    # Check for diagnostic activity
    diag_frames = [f for f in frames if 0x7D0 <= f.arb_id <= 0x7FF]
    if diag_frames:
        anomalies.append({
            "type": "diagnostic_activity",
            "arb_id": "0x7DF-0x7FF",
            "detail": f"{len(diag_frames)} diagnostic frames detected — UDS session activity",
            "severity": "INFO",
        })

    return {
        "total_frames": len(frames),
        "unique_ids": len(id_counts),
        "duration": round(duration, 3),
        "id_distribution": {f"0x{k:03X}": v for k, v in sorted(id_counts.items())},
        "anomalies": anomalies,
        "diagnostic_frames": len(diag_frames) if diag_frames else 0,
    }
