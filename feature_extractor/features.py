from dataclasses import dataclass, asdict, field
from typing import Optional


IDENTIFIER_COLUMNS = [
    "ecosystem",
    "package_name",
    "version",
    "label",
    "source",
    "malicious_type",
]

STATIC_FEATURE_COLUMNS = [
    "has_lifecycle_script",
    "lifecycle_script_count",
    "has_suspicious_script_command",
    "direct_url_dependency_count",      # E. 신규
    "typosquatting_score",              # E. 신규
    "network_api_count",
    "file_api_count",
    "process_api_count",
    "eval_api_count",
    "env_access_count",
    "prototype_assignment_count",       # E. 신규
    "time_based_trigger_count",         # E. 신규
    "credential_keyword_count",
    "has_external_url",
    "url_count",
    "has_obfuscation",
    "base64_string_count",
    "long_string_count",
    "entropy_mean",                     # E. 신규
]

CHAIN_FEATURE_COLUMNS = [
    "chain_env_to_network",
    "chain_file_to_network",
    "chain_download_to_execute",
    "chain_obfuscation_to_eval",
    "chain_lifecycle_to_dangerous_api",
]

CSV_COLUMNS = IDENTIFIER_COLUMNS + STATIC_FEATURE_COLUMNS + CHAIN_FEATURE_COLUMNS


@dataclass
class PackageMeta:
    ecosystem: str = "npm"
    package_name: str = ""
    version: str = ""
    label: int = 0
    source: str = ""
    malicious_type: str = ""


@dataclass
class PackageJsonFeatures:
    has_lifecycle_script: int = 0
    lifecycle_script_count: int = 0
    has_suspicious_script_command: int = 0
    direct_url_dependency_count: int = 0      # 신규: git/url/file: prefix
    typosquatting_score: float = 0.0          # 신규: 유명 패키지명과 Levenshtein
    lifecycle_scripts: dict = field(default_factory=dict)


@dataclass
class AstFeatures:
    network_api_count: int = 0
    file_api_count: int = 0
    process_api_count: int = 0
    eval_api_count: int = 0
    env_access_count: int = 0
    long_string_count: int = 0
    prototype_assignment_count: int = 0       # 신규: X.prototype.Y = ...
    time_based_trigger_count: int = 0         # 신규: Date.getDay/getMonth 등


@dataclass
class RegexFeatures:
    credential_keyword_count: int = 0
    has_external_url: int = 0
    url_count: int = 0
    has_obfuscation: int = 0
    base64_string_count: int = 0
    entropy_mean: float = 0.0                  # 신규: 평균 Shannon entropy


@dataclass
class ChainFeatures:
    chain_env_to_network: int = 0
    chain_file_to_network: int = 0
    chain_download_to_execute: int = 0
    chain_obfuscation_to_eval: int = 0
    chain_lifecycle_to_dangerous_api: int = 0


def to_row(
    meta: PackageMeta,
    pkg: PackageJsonFeatures,
    ast: AstFeatures,
    rgx: RegexFeatures,
    chain: ChainFeatures,
) -> dict:
    row = {}
    row.update(asdict(meta))
    pkg_dict = asdict(pkg)
    pkg_dict.pop("lifecycle_scripts", None)
    row.update(pkg_dict)
    row.update(asdict(ast))
    row.update(asdict(rgx))
    row.update(asdict(chain))
    return {col: row.get(col, 0) for col in CSV_COLUMNS}
