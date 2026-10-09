import hashlib
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from auditlens.schemas.models import EvidenceRecord, ExchangeItem

class EvidenceStore:
    """
    Immutable, cryptographic hash-chained evidence store.
    Guarantees evidence tamper-evidence for all recorded application exchanges.
    """
    def __init__(self):
        self.records: List[EvidenceRecord] = []
        self.last_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"

    def record_exchange(self, exchange: ExchangeItem) -> EvidenceRecord:
        raw_dict = exchange.model_dump()
        payload_str = json.dumps(raw_dict, sort_keys=True)
        
        # Cryptographic block hashing: Hash(Payload || PreviousHash)
        combined = (payload_str + self.last_hash).encode("utf-8")
        current_hash = hashlib.sha256(combined).hexdigest()
        
        rec_id = f"ev-{len(self.records) + 1:04d}"
        record = EvidenceRecord(
            record_id=rec_id,
            timestamp=datetime.utcnow().isoformat(),
            exchange_id=exchange.exchange_id,
            flow_name=exchange.flow_name,
            payload_hash=current_hash,
            previous_hash=self.last_hash,
            raw_data=raw_dict
        )
        self.records.append(record)
        self.last_hash = current_hash
        return record

    def verify_integrity(self) -> bool:
        """Verifies that no record in the evidence chain has been tampered with or modified."""
        prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        for record in self.records:
            if record.previous_hash != prev_hash:
                return False
            payload_str = json.dumps(record.raw_data, sort_keys=True)
            combined = (payload_str + prev_hash).encode("utf-8")
            expected_hash = hashlib.sha256(combined).hexdigest()
            if record.payload_hash != expected_hash:
                return False
            prev_hash = record.payload_hash
        return True

    def get_records_for_exchange(self, exchange_id: str) -> List[EvidenceRecord]:
        return [r for r in self.records if r.exchange_id == exchange_id]
