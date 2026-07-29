"""Launch a daemon or proxy one untouched command path and argv to it.

Application verbs live with fact families; this process only renders replies.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_NODE = "http://127.0.0.1:7100"
USAGE = (
    "usage: core [--node URL] <scope.family.verb> [args...]\n"
    "       core daemon <dir> [--port PORT]\n"
    "       core --commands"
)


def ctl(node_url, path, argv):
    """Send the control plane's one command envelope."""
    request = urllib.request.Request(
        f"{node_url}/ctl/command",
        data=json.dumps({"path": path, "argv": argv}).encode(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def _serve(argv):
    parser = argparse.ArgumentParser(prog="core daemon")
    parser.add_argument("dir")
    parser.add_argument("--port", type=int, default=7100)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--cadence", type=float, default=1.0)
    parser.add_argument("--url")
    args = parser.parse_args(argv)
    from .daemon import serve
    return serve(
        args.dir, args.port, args.host, args.cadence, args.url)


def _commands():
    from .daemon import CORE_COMMANDS
    from facts import COMMANDS
    return tuple(sorted((*CORE_COMMANDS, *COMMANDS)))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    node_url = DEFAULT_NODE
    if argv[:1] == ["--node"]:
        if len(argv) < 2:
            raise SystemExit("--node requires a URL")
        node_url, argv = argv[1], argv[2:]

    if argv[:1] == ["daemon"]:
        return _serve(argv[1:])
    if argv == ["--commands"]:
        print("\n".join(_commands()))
        return 0
    if argv in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if not argv:
        raise SystemExit(USAGE)

    path, *tokens = argv
    try:
        out = ctl(node_url, path, tokens)
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read()).get("error", error.reason)
        except (AttributeError, json.JSONDecodeError, UnicodeDecodeError):
            detail = error.reason
        print(f"core: {error.code}: {detail}", file=sys.stderr)
        return 1
    if isinstance(out, str):
        print(out)
    else:
        json.dump(out, sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
