import json
import os
from typing import List, Dict, Any, Optional
from auditlens.schemas.models import AppProfile, ExchangeItem

class BaseAdapter:
    """Abstract interface for AuditLens Target Application Adapters."""
    def get_application_profile(self) -> AppProfile:
        raise NotImplementedError
    def list_datasets(self) -> List[str]:
        raise NotImplementedError
    def list_flows(self, dataset: str) -> List[str]:
        raise NotImplementedError
    def get_exchanges(self, dataset: str, flow: str) -> List[Any]:
        raise NotImplementedError

class SharePackageAdapter(BaseAdapter):
    """
    Adapter designed specifically for reading recorded datasets from the 'share/' directory
    (Resume/JD screening service datasets & Support-ticket RAG chatbot datasets).
    """
    def __init__(self, package_dir: str):
        self.package_dir = os.path.abspath(package_dir)
        self.profile_path = os.path.join(self.package_dir, "application_profile.json")
        self._load_profile()

    def _load_profile(self):
        if not os.path.exists(self.profile_path):
            raise FileNotFoundError(f"Application profile not found at {self.profile_path}")
        
        with open(self.profile_path, "r", encoding="utf-8") as f:
            raw_profile = json.load(f)

        # Normalize raw application_profile.json into AppProfile model
        app_id = "resume_service" if "Resume" in raw_profile.get("name", "") else "rag_chatbot"
        data_handled = raw_profile.get("data_handled", [])
        
        roles = []
        if isinstance(raw_profile.get("roles"), dict):
            roles = list(raw_profile.get("roles").keys())
        elif isinstance(raw_profile.get("roles"), list):
            roles = raw_profile.get("roles")

        stated_policies = raw_profile.get("stated_policies", {})
        residency_rules = {}
        if "allowed_model_regions" in stated_policies:
            residency_rules["allowed_regions"] = stated_policies["allowed_model_regions"]
        elif "allowed_regions" in stated_policies:
            residency_rules["allowed_regions"] = stated_policies["allowed_regions"]

        retention_days = {"retention": stated_policies.get("retention_days", 30)}

        self.profile = AppProfile(
            app_id=app_id,
            name=raw_profile.get("name", "Target Application"),
            purpose=raw_profile.get("purpose", ""),
            kind=raw_profile.get("kind", "rag_app"),
            data_handled=data_handled,
            roles=roles,
            residency_rules=residency_rules,
            retention_days=retention_days,
            policy_locations=stated_policies.get("where_to_read", []),
            audit_level="L3 Config"
        )

    def get_application_profile(self) -> AppProfile:
        return self.profile

    def list_datasets(self) -> List[str]:
        # Handle resume_datasets (inside ./datasets) vs rag_datasets (rag_a, rag_b directly)
        ds_dir = os.path.join(self.package_dir, "datasets")
        if os.path.exists(ds_dir) and os.path.isdir(ds_dir):
            return sorted([d for d in os.listdir(ds_dir) if os.path.isdir(os.path.join(ds_dir, d))])
        
        # Check rag_datasets
        datasets = []
        for item in os.listdir(self.package_dir):
            if item.startswith("rag_") and os.path.isdir(os.path.join(self.package_dir, item)):
                datasets.append(item)
        return sorted(datasets)

    def _dataset_dir(self, dataset: str) -> str:
        ds_dir = os.path.join(self.package_dir, "datasets", dataset)
        if os.path.exists(ds_dir):
            return ds_dir
        
        rag_dir = os.path.join(self.package_dir, dataset)
        if os.path.exists(rag_dir):
            return rag_dir
        
        raise KeyError(f"Unknown dataset '{dataset}' in {self.package_dir}")

    def list_flows(self, dataset: str) -> List[str]:
        target_dir = self._dataset_dir(dataset)
        flows = []
        for file_name in os.listdir(target_dir):
            if file_name.endswith(".json"):
                flows.append(file_name.replace(".json", ""))
        return sorted(flows)

    def get_exchanges(self, dataset: str, flow: str) -> List[Any]:
        target_dir = self._dataset_dir(dataset)
        file_path = os.path.join(target_dir, f"{flow}.json")
        if not os.path.exists(file_path):
            raise KeyError(f"Unknown flow '{flow}' in dataset '{dataset}'")
        
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "exchanges" in data:
                return data["exchanges"]
            return data if isinstance(data, list) else [data]

    def get_response(self, dataset: str, flow: str, index: int = 0) -> Any:
        exchanges = self.get_exchanges(dataset, flow)
        if not 0 <= index < len(exchanges):
            raise IndexError(f"Index {index} out of bounds for flow {flow}")
        item = exchanges[index]
        if isinstance(item, dict):
            return item.get("response", item)
        return item
