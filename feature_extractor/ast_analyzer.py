from pathlib import Path
from typing import Iterable

import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Node

from .features import AstFeatures


JS_LANGUAGE = Language(tsjs.language())
_parser = Parser(JS_LANGUAGE)

NETWORK_MODULES = {"http", "https", "net", "dns", "tls", "http2", "dgram"}
NETWORK_LIBS = {"axios", "node-fetch", "request", "got", "superagent", "undici", "isomorphic-fetch"}
NETWORK_GLOBALS = {"fetch"}
NETWORK_MEMBER_OBJECTS = {"http", "https", "axios", "fetch"}
NETWORK_MEMBER_PROPS = {"request", "get", "post", "put", "delete", "patch"}

FILE_MODULES = {"fs", "fs/promises", "node:fs", "node:fs/promises", "path"}
FILE_MEMBER_OBJECTS = {"fs", "fsp", "fsPromises"}
FILE_MEMBER_PROPS = {
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "appendFile", "appendFileSync", "readdir", "readdirSync",
    "chmod", "chmodSync", "rename", "renameSync", "unlink", "unlinkSync",
    "createReadStream", "createWriteStream",
}

PROCESS_MODULES = {"child_process", "node:child_process"}
PROCESS_MEMBER_OBJECTS = {"child_process", "cp"}
PROCESS_MEMBER_PROPS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}

EVAL_GLOBALS = {"eval"}
EVAL_CONSTRUCTORS = {"Function"}

LONG_STRING_THRESHOLD = 100

# 시한폭탄 탐지: Date 객체의 시간 조회 메서드
TIME_METHODS = {
    "getDay", "getMonth", "getFullYear", "getDate",
    "getHours", "getMinutes", "getTime",
}


def analyze_files(files: Iterable[Path]) -> AstFeatures:
    agg = AstFeatures()
    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        feats = _analyze_source(source)
        agg.network_api_count += feats.network_api_count
        agg.file_api_count += feats.file_api_count
        agg.process_api_count += feats.process_api_count
        agg.eval_api_count += feats.eval_api_count
        agg.env_access_count += feats.env_access_count
        agg.long_string_count += feats.long_string_count
        agg.prototype_assignment_count += feats.prototype_assignment_count
        agg.time_based_trigger_count += feats.time_based_trigger_count
    return agg


def _analyze_source(source: bytes) -> AstFeatures:
    feats = AstFeatures()
    try:
        tree = _parser.parse(source)
    except Exception:
        return feats

    _walk(tree.root_node, source, feats)
    return feats


def _walk(root: Node, source: bytes, feats: AstFeatures) -> None:
    # Iterative traversal — Python의 재귀 한계(기본 1000)를 회피.
    # aws-sdk, playwright-core 같이 깊이 1000+인 AST에서 RecursionError 방지.
    stack = [root]
    while stack:
        node = stack.pop()
        t = node.type
        if t == "call_expression":
            _handle_call(node, source, feats)
        elif t == "member_expression":
            _handle_member(node, source, feats)
        elif t == "new_expression":
            _handle_new(node, source, feats)
        elif t == "assignment_expression":
            _handle_assignment(node, source, feats)
        elif t == "string" or t == "template_string":
            if (node.end_byte - node.start_byte) >= LONG_STRING_THRESHOLD:
                feats.long_string_count += 1
        stack.extend(node.children)


def _handle_assignment(node: Node, source: bytes, feats: AstFeatures) -> None:
    """X.prototype.Y = ... 패턴 탐지 (evil.js류 sabotage)."""
    left = node.child_by_field_name("left")
    if left is None or left.type != "member_expression":
        return
    # left.object 가 다시 member_expression 이고, 그 property 가 "prototype" 이면 매칭
    obj = left.child_by_field_name("object")
    if obj is None or obj.type != "member_expression":
        return
    prop = obj.child_by_field_name("property")
    if prop is not None and _text(prop, source) == "prototype":
        feats.prototype_assignment_count += 1


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _handle_call(node: Node, source: bytes, feats: AstFeatures) -> None:
    func = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    if func is None:
        return

    # require("...") / import("...")
    fname = _text(func, source)
    if fname in {"require", "import"} and args is not None:
        mod = _first_string_arg(args, source)
        if mod is None:
            return
        if mod in NETWORK_MODULES or mod in NETWORK_LIBS:
            feats.network_api_count += 1
        elif mod in FILE_MODULES:
            feats.file_api_count += 1
        elif mod in PROCESS_MODULES:
            feats.process_api_count += 1
        return

    # eval(...), Function(...), fetch(...)
    if func.type == "identifier":
        ident = fname
        if ident in EVAL_GLOBALS:
            feats.eval_api_count += 1
        elif ident in NETWORK_GLOBALS:
            feats.network_api_count += 1

    # obj.method(...)
    if func.type == "member_expression":
        obj_node = func.child_by_field_name("object")
        prop_node = func.child_by_field_name("property")
        if obj_node is None or prop_node is None:
            return
        obj = _text(obj_node, source)
        prop = _text(prop_node, source)
        if obj in NETWORK_MEMBER_OBJECTS and prop in NETWORK_MEMBER_PROPS:
            feats.network_api_count += 1
        elif obj in FILE_MEMBER_OBJECTS and prop in FILE_MEMBER_PROPS:
            feats.file_api_count += 1
        elif obj in PROCESS_MEMBER_OBJECTS and prop in PROCESS_MEMBER_PROPS:
            feats.process_api_count += 1
        # 시한폭탄: Date 인스턴스의 시간 메서드 호출 (예: new Date().getDay())
        if prop in TIME_METHODS:
            feats.time_based_trigger_count += 1


def _handle_member(node: Node, source: bytes, feats: AstFeatures) -> None:
    obj_node = node.child_by_field_name("object")
    prop_node = node.child_by_field_name("property")
    if obj_node is None or prop_node is None:
        return
    if _text(obj_node, source) == "process" and _text(prop_node, source) == "env":
        feats.env_access_count += 1


def _handle_new(node: Node, source: bytes, feats: AstFeatures) -> None:
    ctor = node.child_by_field_name("constructor")
    if ctor is not None and _text(ctor, source) in EVAL_CONSTRUCTORS:
        feats.eval_api_count += 1


def _first_string_arg(args_node: Node, source: bytes) -> str | None:
    for child in args_node.children:
        if child.type == "string":
            raw = _text(child, source)
            if len(raw) >= 2 and raw[0] in {"'", '"', "`"}:
                return raw[1:-1]
            return raw
    return None
