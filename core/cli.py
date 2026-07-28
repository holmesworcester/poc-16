"""CLI: `core daemon` runs a node; every other command drives a running
daemon over its control plane — the black-box seam the tests use too."""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def ctl(node_url, method, path, body=None, **q):
    qs = urllib.parse.urlencode({k: v for k, v in q.items() if v})
    req = urllib.request.Request(
        f"{node_url}/ctl/{path}" + (f"?{qs}" if qs else ""),
        data=json.dumps(body).encode() if body is not None else None, method=method)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def run_command(a):
    if a.cmd == "create":
        return ctl(a.node, "POST", "create", {"name": a.name})
    if a.cmd == "invite":
        return ctl(a.node, "POST", "invite", {"ws": a.ws})
    if a.cmd == "join":
        return ctl(
            a.node, "POST", "join", {"link": a.link, "name": a.name})
    if a.cmd == "post":
        return ctl(
            a.node, "POST", "post",
            {"ws": a.ws, "chan": a.chan or "general", "text": a.text})
    if a.cmd == "send":
        with open(a.path, "rb") as source:
            data = source.read()
        return ctl(
            a.node, "POST", "send",
            {"ws": a.ws, "chan": a.chan or "general",
             "name": a.path.rsplit("/", 1)[-1],
             "data": base64.b64encode(data).decode()})
    if a.cmd == "get":
        out = ctl(a.node, "GET", "file", ws=a.ws, fid=a.fid)
        raw = base64.b64decode(out.pop("data"))
        path = a.out or out["name"]
        with open(path, "wb") as target:
            target.write(raw)
        out["wrote"] = path
        return out
    if a.cmd == "evict":
        return ctl(
            a.node, "POST", "evict", {"ws": a.ws, "member": a.member})
    if a.cmd == "remove":
        return ctl(
            a.node, "POST", "remove", {"ws": a.ws, "fid": a.fid})
    if a.cmd == "msgs":
        return ctl(a.node, "GET", "msgs", ws=a.ws, chan=a.chan)
    if a.cmd == "members":
        return ctl(a.node, "GET", "members", ws=a.ws)
    if a.cmd == "files":
        return ctl(a.node, "GET", "files", ws=a.ws)
    if a.cmd == "status":
        return ctl(a.node, "GET", "status")
    if a.cmd == "sync":
        return ctl(a.node, "POST", "sync", {"ws": a.ws})
    if a.cmd == "rebuild":
        return ctl(a.node, "POST", "rebuild", {"ws": a.ws})
    raise ValueError(f"unknown command: {a.cmd}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="core")
    p.add_argument("--node", default="http://127.0.0.1:7100", help="daemon base URL")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("daemon")
    d.add_argument("dir")
    d.add_argument("--port", type=int, default=7100)
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--cadence", type=float, default=1.0)
    d.add_argument("--url")

    for name, args in {
        "create": [("name",)], "invite": [("--ws",)],
        "join": [("link",), ("name",)],
        "post": [("--ws",), ("--chan",), ("text",)],
        "send": [("--ws",), ("--chan",), ("path",)],
        "get": [("--ws",), ("fid",), ("--out",)],
        "evict": [("--ws",), ("member",)],
        "remove": [("--ws",), ("fid",)],
        "msgs": [("--ws",), ("--chan",)], "members": [("--ws",)],
        "files": [("--ws",)], "status": [], "sync": [("--ws",)],
        "rebuild": [("--ws",)],
    }.items():
        s = sub.add_parser(name)
        for (a,) in args:
            s.add_argument(a) if not a.startswith("--") else s.add_argument(a, default="")

    a = p.parse_args(argv)
    if a.cmd == "daemon":
        from .daemon import serve
        return serve(a.dir, a.port, a.host, a.cadence, a.url)

    try:
        out = run_command(a)
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read()).get("error", error.reason)
        except (AttributeError, json.JSONDecodeError, UnicodeDecodeError):
            detail = error.reason
        print(f"core: {error.code}: {detail}", file=sys.stderr)
        return 1
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
