"""Launch a daemon or proxy one untouched command path and argv to it.

Application verbs live with fact families; this process only renders replies.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from core.http_body import read_bounded
from core.http_stdlib import HttpGateOptions
from core.limits import (
    MAX_CONTROL_BYTES,
    MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES,
)

DEFAULT_NODE = "http://127.0.0.1:7101"
USAGE = (
    "usage: full_peer [--node URL] <scope.family.verb> [args...]\n"
    "       full_peer daemon <dir> [--port PORT] [--control-port PORT] "
    "[--iroh] [--enable-experimental-notifications]\n"
    "       full_peer --commands"
)
STORE_HELP = """\
Cloud object stores use a strict JSON file passed with --store-config.
Credentials are not allowed in that file; boto uses its normal environment,
shared-config, container, or instance credential chain.

Amazon S3:
  {"schema":"poc16-host-store-v1","backend":"s3",
   "bucket":"my-bucket","base_prefix":"poc16/tenant",
   "region_name":"us-west-2"}

Cloudflare R2 (use the direct account endpoint derived from account_id):
  {"schema":"poc16-host-store-v1","backend":"r2",
   "account_id":"0123456789abcdef0123456789abcdef",
   "bucket":"my-bucket","base_prefix":"poc16/tenant"}
"""


def ctl(node_url, path, argv):
    """Send the control plane's one command envelope."""
    request = urllib.request.Request(
        f"{node_url}/ctl/command",
        data=json.dumps({"path": path, "argv": argv}).encode(),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(read_bounded(
            response, MAX_CONTROL_BYTES, "control response"))


def _gate_options(environ=None):
    """Read process configuration once into one immutable validated value."""
    environ = os.environ if environ is None else environ

    def integer(name, default):
        try:
            return int(environ.get(name, default))
        except (TypeError, ValueError) as error:
            raise RuntimeError(f"invalid {name}") from error

    try:
        return HttpGateOptions(
            grant_ttl_ms=integer("TINYP2P_GRANT_TTL", 60_000),
            max_mint_fetches=integer(
                "TINYP2P_MINT_MAX_FETCHES", MAX_MINT_FETCHES),
            max_mint_fetch_bytes=integer(
                "TINYP2P_MINT_MAX_FETCH_BYTES", MAX_MINT_FETCH_BYTES),
        )
    except ValueError as error:
        raise RuntimeError(
            "invalid full-peer HTTP gate configuration") from error


def _serve(argv):
    parser = argparse.ArgumentParser(
        prog="full_peer daemon",
        description="Run one local client node and its HTTP responder.",
        epilog=STORE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("dir")
    parser.add_argument("--port", type=int, default=7100)
    parser.add_argument("--control-port", type=int, default=7101)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--cadence", type=float, default=1.0)
    parser.add_argument("--url")
    parser.add_argument(
        "--iroh", action="store_true",
        help="wrap the loopback peer-data listener in supervised Iroh")
    parser.add_argument(
        "--iroh-binary",
        default=os.environ.get("POC16_IROH_BINARY", "poc16-iroh"),
        help="poc16-iroh executable (default: POC16_IROH_BINARY or PATH)")
    parser.add_argument(
        "--iroh-key-file",
        help="stable endpoint key (default: DIR/iroh/endpoint.key)")
    parser.add_argument(
        "--iroh-loopback", action="store_true",
        help="disable relay/discovery for a local test or demo")
    parser.add_argument(
        "--store-config", metavar="PATH",
        help="strict S3/R2 host-store JSON (default: local filesystem)")
    parser.add_argument(
        "--enable-experimental-notifications", action="store_true",
        help="enable default-off FactTree scanning and FCM delivery")
    parser.add_argument(
        "--notification-cadence", type=float, default=30.0,
        help="notification scan cadence in seconds (default: 30)")
    parser.add_argument(
        "--notification-application",
        help="fact application mapped to the Firebase default app")
    parser.add_argument(
        "--notification-environment", default="production",
        help="fact environment mapped to the Firebase default app")
    args = parser.parse_args(argv)
    if not args.iroh and (
            args.iroh_key_file is not None or args.iroh_loopback):
        parser.error("--iroh-key-file/--iroh-loopback require --iroh")
    if args.enable_experimental_notifications \
            and args.notification_application is None:
        parser.error(
            "--notification-application is required with "
            "--enable-experimental-notifications")
    if not args.enable_experimental_notifications and (
            args.notification_application is not None
            or args.notification_cadence != 30.0
            or args.notification_environment != "production"):
        parser.error(
            "notification options require "
            "--enable-experimental-notifications")
    store_factory = None
    if args.store_config is not None:
        from adapters.host import load_store_factory
        store_factory = load_store_factory(args.store_config)
    notification_provider = None
    if args.enable_experimental_notifications:
        from .notifications import firebase_from_default_credentials
        notification_provider = firebase_from_default_credentials(
            args.notification_application,
            args.notification_environment,
        )
    from .daemon import serve
    return serve(
        args.dir, args.port, args.host, args.cadence, args.url,
        control_port=args.control_port,
        store_factory=store_factory,
        gate_options=_gate_options(),
        iroh_binary=args.iroh_binary if args.iroh else None,
        iroh_key_file=args.iroh_key_file,
        iroh_loopback=args.iroh_loopback,
        notification_enabled=args.enable_experimental_notifications,
        notification_cadence=args.notification_cadence,
        notification_provider=notification_provider,
    )


def _commands():
    from .daemon import LOCAL_COMMANDS
    from facts import COMMANDS
    return tuple(sorted((*LOCAL_COMMANDS, *COMMANDS)))


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
            raw = read_bounded(
                error, MAX_CONTROL_BYTES, "control error response")
            detail = json.loads(raw).get("error", error.reason)
        except (
                AttributeError,
                json.JSONDecodeError,
                UnicodeDecodeError,
                ValueError,
        ):
            detail = error.reason
        finally:
            error.close()
        print(f"full_peer: {error.code}: {detail}", file=sys.stderr)
        return 1
    if isinstance(out, str):
        print(out)
    else:
        json.dump(out, sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
