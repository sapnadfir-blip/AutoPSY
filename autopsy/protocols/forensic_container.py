"""
Forensic evidence container — chain-of-custody aware storage for vehicle evidence.

Wraps all captured evidence (CAN frames, SOME/IP packets, DoIP sessions, ECU data)
into a single container with SHA-256 hashing for integrity verification.

Container format:
  - JSON metadata header (examiner, case, vehicle, acquisition time)
  - Evidence blocks with individual hashes
  - Master hash covering all evidence
"""
import json
import hashlib
import time
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any


@dataclass
class EvidenceBlock:
    block_id: str = ""
    block_type: str = ""  # "can_capture", "someip_capture", "doip_session", "ecu_data", "dtc_data"
    source: str = ""
    timestamp: float = 0.0
    data: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)
    sha256: str = ""

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if not self.sha256 and self.data:
            self.sha256 = hashlib.sha256(self.data).hexdigest()

    def to_dict(self) -> dict:
        return {
            "block_id": self.block_id,
            "block_type": self.block_type,
            "source": self.source,
            "timestamp": self.timestamp,
            "data_size": len(self.data),
            "data_hex": self.data[:256].hex() if self.data else "",
            "metadata": self.metadata,
            "sha256": self.sha256,
        }


@dataclass
class CaseInfo:
    case_id: str = ""
    examiner: str = ""
    organization: str = ""
    vehicle_vin: str = ""
    vehicle_make: str = ""
    vehicle_model: str = ""
    vehicle_year: str = ""
    incident_date: str = ""
    incident_description: str = ""
    acquisition_date: str = ""
    notes: str = ""


@dataclass
class ForensicContainer:
    case_info: CaseInfo = field(default_factory=CaseInfo)
    evidence_blocks: List[EvidenceBlock] = field(default_factory=list)
    created: float = 0.0
    tool_version: str = "AutoPSY 1.0.0"
    master_hash: str = ""

    def __post_init__(self):
        if self.created == 0.0:
            self.created = time.time()

    def add_evidence(self, block: EvidenceBlock) -> str:
        if not block.block_id:
            block.block_id = f"EVD-{len(self.evidence_blocks)+1:04d}"
        if not block.sha256 and block.data:
            block.sha256 = hashlib.sha256(block.data).hexdigest()
        self.evidence_blocks.append(block)
        self._update_master_hash()
        return block.block_id

    def _update_master_hash(self):
        hasher = hashlib.sha256()
        hasher.update(json.dumps(asdict(self.case_info)).encode())
        for block in self.evidence_blocks:
            hasher.update(block.sha256.encode())
        self.master_hash = hasher.hexdigest()

    def verify_integrity(self) -> Dict[str, Any]:
        results = {"valid": True, "blocks_checked": 0, "failures": []}
        for block in self.evidence_blocks:
            results["blocks_checked"] += 1
            if block.data:
                computed = hashlib.sha256(block.data).hexdigest()
                if computed != block.sha256:
                    results["valid"] = False
                    results["failures"].append({
                        "block_id": block.block_id,
                        "expected": block.sha256,
                        "computed": computed,
                    })

        expected_master = hashlib.sha256()
        expected_master.update(json.dumps(asdict(self.case_info)).encode())
        for block in self.evidence_blocks:
            expected_master.update(block.sha256.encode())
        if expected_master.hexdigest() != self.master_hash:
            results["valid"] = False
            results["failures"].append({"type": "master_hash_mismatch"})

        return results

    def save(self, path: str):
        container_data = {
            "autopsy_version": self.tool_version,
            "created": self.created,
            "case_info": asdict(self.case_info),
            "evidence_count": len(self.evidence_blocks),
            "evidence_blocks": [b.to_dict() for b in self.evidence_blocks],
            "master_hash": self.master_hash,
        }
        with open(path, "w") as f:
            json.dump(container_data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "ForensicContainer":
        with open(path) as f:
            data = json.load(f)
        container = cls()
        container.tool_version = data.get("autopsy_version", "unknown")
        container.created = data.get("created", 0)
        container.master_hash = data.get("master_hash", "")
        ci = data.get("case_info", {})
        container.case_info = CaseInfo(**{k: v for k, v in ci.items() if k in CaseInfo.__dataclass_fields__})
        for bd in data.get("evidence_blocks", []):
            block = EvidenceBlock(
                block_id=bd.get("block_id", ""),
                block_type=bd.get("block_type", ""),
                source=bd.get("source", ""),
                timestamp=bd.get("timestamp", 0),
                data=bytes.fromhex(bd.get("data_hex", "")),
                metadata=bd.get("metadata", {}),
                sha256=bd.get("sha256", ""),
            )
            container.evidence_blocks.append(block)
        return container

    def summary(self) -> Dict[str, Any]:
        type_counts = {}
        total_bytes = 0
        for b in self.evidence_blocks:
            type_counts[b.block_type] = type_counts.get(b.block_type, 0) + 1
            total_bytes += len(b.data)
        return {
            "case_id": self.case_info.case_id,
            "vehicle_vin": self.case_info.vehicle_vin,
            "examiner": self.case_info.examiner,
            "evidence_blocks": len(self.evidence_blocks),
            "evidence_types": type_counts,
            "total_evidence_bytes": total_bytes,
            "master_hash": self.master_hash[:16] + "...",
            "integrity": self.verify_integrity()["valid"],
        }
