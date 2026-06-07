import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from .features import RegexFeatures


URL_RE = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)

CREDENTIAL_RE = re.compile(
    r"\.npmrc|\.env\b|NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|"
    r"PRIVATE_KEY|BEGIN\s+RSA\s+PRIVATE|SSH_AUTH|GOOGLE_APPLICATION_CREDENTIALS",
    re.IGNORECASE,
)

# base64-ish runs >= 80 chars
BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{80,}")
# hex string runs >= 80 chars
HEX_RE = re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}")


def analyze_files(files: Iterable[Path]) -> RegexFeatures:
    agg = RegexFeatures()
    entropies = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        feats = _analyze_text(text)
        agg.credential_keyword_count += feats.credential_keyword_count
        agg.url_count += feats.url_count
        agg.base64_string_count += feats.base64_string_count
        e = _shannon_entropy(text)
        if e > 0:
            entropies.append(e)

    agg.has_external_url = int(agg.url_count > 0)
    agg.has_obfuscation = int(agg.base64_string_count > 0)
    agg.entropy_mean = sum(entropies) / len(entropies) if entropies else 0.0
    return agg


def _analyze_text(text: str) -> RegexFeatures:
    feats = RegexFeatures()
    feats.url_count = len(URL_RE.findall(text))
    feats.credential_keyword_count = len(CREDENTIAL_RE.findall(text))
    feats.base64_string_count = len(BASE64_RE.findall(text)) + len(HEX_RE.findall(text))
    return feats


def _shannon_entropy(text: str) -> float:
    """파일 텍스트의 문자 분포 Shannon entropy.
    정상 JS 코드: 약 4.5~5.5
    난독화/base64/encoded payload: 약 5.5~7.0
    """
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
