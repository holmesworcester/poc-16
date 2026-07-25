"""CLI: `core daemon` runs a node; every other command drives a running
daemon over its control plane — the black-box seam the tests use too."""
import argparse
import base64
import json
import sys
import urllib.parse
import urllib.request


def ctl(node_url, method, path, body=None, **q):
    qs = urllib.parse.urlencode({k: v for k, v in q.items() if v})
    req = urllib.request.Request(
        f"{node_url}/ctl/{path}" + (f"?{qs}" if qs else ""),
        data=json.dumps(body).encode() if body is not None else None, method=method)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


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

    if a.cmd == "create":
        out = ctl(a.node, "POST", "create", {"name": a.name})
    elif a.cmd == "invite":
        out = ctl(a.node, "POST", "invite", {"ws": a.ws})
    elif a.cmd == "join":
        out = ctl(a.node, "POST", "join", {"link": a.link, "name": a.name})
    elif a.cmd == "post":
        out = ctl(a.node, "POST", "post", {"ws": a.ws, "chan": a.chan or "general", "text": a.text})
    elif a.cmd == "send":
        data = open(a.path, "rb").read()
        out = ctl(a.node, "POST", "send", {"ws": a.ws, "chan": a.chan or "general",
                                           "name": a.path.rsplit("/", 1)[-1],
                                           "data": base64.b64encode(data).decode()})
    elif a.cmd == "get":
        out = ctl(a.node, "GET", "file", ws=a.ws, fid=a.fid)
        raw = base64.b64decode(out.pop("data"))
        path = a.out or out["name"]
        open(path, "wb").write(raw)
        out["wrote"] = path
    elif a.cmd == "evict":
        out = ctl(a.node, "POST", "evict", {"ws": a.ws, "member": a.member})
    elif a.cmd == "msgs":
        out = ctl(a.node, "GET", "msgs", ws=a.ws, chan=a.chan)
    elif a.cmd == "members":
        out = ctl(a.node, "GET", "members", ws=a.ws)
    elif a.cmd == "files":
        out = ctl(a.node, "GET", "files", ws=a.ws)
    elif a.cmd == "status":
        out = ctl(a.node, "GET", "status")
    elif a.cmd == "sync":
        out = ctl(a.node, "POST", "sync", {"ws": a.ws})
    elif a.cmd == "rebuild":
        out = ctl(a.node, "POST", "rebuild", {"ws": a.ws})
    json.dump(out, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
