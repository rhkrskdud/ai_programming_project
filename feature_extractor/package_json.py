import json
import re
from pathlib import Path

from .features import PackageJsonFeatures, PackageMeta


LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare", "preuninstall", "uninstall")

SUSPICIOUS_COMMAND_PATTERNS = [
    r"\bcurl\b",
    r"\bwget\b",
    r"\bbash\b",
    r"\bsh\b",
    r"\bpowershell\b",
    r"\bnode\s+-e\b",
    r"\bchmod\b",
    r"\brm\s+-rf\b",
    r"\beval\b",
    r"\bbase64\b",
]
SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_COMMAND_PATTERNS), re.IGNORECASE)

# 공급망 우회 의심 의존성 prefix
URL_DEP_PREFIXES = ("git+", "git://", "http://", "https://", "file:", "github:", "gitlab:", "bitbucket:")

DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")

# Top 100 most popular npm packages — typosquatting 비교 대상
# (실시간 npm registry 조회 대신 임베드 — 발표 단계 단순화용)
TOP_PACKAGES = frozenset({
    "lodash", "react", "express", "axios", "moment", "uuid", "request", "jquery",
    "vue", "angular", "typescript", "webpack", "eslint", "prettier", "jest",
    "mocha", "chalk", "commander", "glob", "fs-extra", "async", "body-parser",
    "cheerio", "dotenv", "debug", "semver", "yargs", "minimist", "rxjs",
    "react-dom", "react-router", "redux", "babel-core", "babel-loader",
    "babel-preset-env", "css-loader", "style-loader", "html-webpack-plugin",
    "mini-css-extract-plugin", "postcss", "sass", "node-sass", "tailwindcss",
    "bootstrap", "next", "nuxt", "gatsby", "svelte", "preact", "ember",
    "backbone", "underscore", "ramda", "immutable", "rimraf", "mkdirp",
    "is-promise", "ms", "ansi-styles", "supports-color", "color-name",
    "color-convert", "kind-of", "is-extendable", "for-in", "object-assign",
    "graceful-fs", "readable-stream", "string-width", "ansi-regex", "strip-ansi",
    "isarray", "process-nextick-args", "safe-buffer", "wrappy", "once",
    "node-fetch", "form-data", "got", "isomorphic-fetch", "cross-fetch",
    "tslib", "core-js", "regenerator-runtime", "@babel/runtime", "lru-cache",
    "ws", "socket.io", "passport", "jsonwebtoken", "bcrypt", "mongoose",
    "sequelize", "pg", "mysql", "redis", "ioredis", "mongodb", "knex",
    "winston", "pino", "morgan",
})


def parse(package_root: Path) -> tuple[PackageMeta, PackageJsonFeatures]:
    meta = PackageMeta()
    feats = PackageJsonFeatures()

    pj = package_root / "package.json"
    if not pj.exists():
        return meta, feats

    try:
        data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return meta, feats

    meta.package_name = str(data.get("name", "") or "")
    meta.version = str(data.get("version", "") or "")

    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        lifecycle = {k: v for k, v in scripts.items() if k in LIFECYCLE_KEYS and isinstance(v, str)}
        feats.lifecycle_scripts = lifecycle
        feats.lifecycle_script_count = len(lifecycle)
        feats.has_lifecycle_script = int(bool(lifecycle))
        joined = "\n".join(lifecycle.values())
        feats.has_suspicious_script_command = int(bool(SUSPICIOUS_RE.search(joined)))

    feats.direct_url_dependency_count = _count_url_deps(data)
    feats.typosquatting_score = _typosquatting_score(meta.package_name)

    return meta, feats


def _count_url_deps(data: dict) -> int:
    """package.json의 의존성에서 git/url/file: prefix 가진 항목 카운트."""
    count = 0
    for field in DEP_FIELDS:
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for spec in deps.values():
            if isinstance(spec, str) and spec.lower().startswith(URL_DEP_PREFIXES):
                count += 1
    return count


def _typosquatting_score(name: str) -> float:
    """유명 패키지명과의 최소 Levenshtein 거리 기반 점수.
    - 자기 자신이 유명 패키지: 0 (정상)
    - 거리 1 (1글자 차이): 3.0 (강한 신호)
    - 거리 2: 2.0
    - 거리 3: 1.0
    - 거리 ≥ 4: 0 (무관)
    - scoped (@x/y) 패키지는 본명만 비교
    """
    if not name:
        return 0.0
    base = name.split("/")[-1].lower()
    if base in TOP_PACKAGES:
        return 0.0
    min_dist = 99
    for top in TOP_PACKAGES:
        d = _levenshtein(base, top, limit=4)
        if d < min_dist:
            min_dist = d
            if min_dist == 1:
                break
    if min_dist == 1:
        return 3.0
    if min_dist == 2:
        return 2.0
    if min_dist == 3:
        return 1.0
    return 0.0


def _levenshtein(a: str, b: str, limit: int = 99) -> int:
    """단순 Levenshtein, 길이 차이가 limit 초과면 early exit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, 1):
        curr = [i]
        row_min = i
        for j, ca in enumerate(a, 1):
            curr.append(min(
                curr[-1] + 1,
                prev[j] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            ))
            if curr[-1] < row_min:
                row_min = curr[-1]
        if row_min > limit:
            return limit + 1
        prev = curr
    return prev[-1]
