"""Shared mechanics for family commands; no fact policy lives here."""
import os


def offer_source(node, workspace, name, a0, a1=None, requires=()):
    """Return the current live provider from one pinned repository root."""
    with node.lock:
        reader = node.reader(workspace)
        return None if reader is None else reader.worker().authority_provider(
            name, a0, a1, requires)


def member_key(node, workspace, target):
    """Resolve a command target: exact public key first, unique name second."""
    from .auth.user import members

    roster = members(node, workspace)
    if any(row["pk"] == target for row in roster):
        return target
    named = sorted(
        row["pk"] for row in roster if row["name"] == target)
    if not named:
        raise ValueError(f"no member {target!r}")
    if len(named) != 1:
        raise ValueError(f"ambiguous member name {target!r}")
    return named[0]


def publish(node, workspace, fact, signature, role="member"):
    """Close one signed fact with its local authority edge and ingest it."""
    authors = [
        public_key
        for name, target, public_key in signature.offers()
        if name == "author" and target == fact.fid
    ]
    if len(authors) != 1:
        raise ValueError("signature does not author the published fact")
    public_key = authors[0]
    src = offer_source(node, workspace, role, public_key)
    if src is None:
        raise ValueError(
            f"publishing identity is not a workspace {role}")
    deps = {fact.fid: [r for _, r in fact.refs()] + [signature.fid]
            + [src], signature.fid: []}
    node.ingest_new(workspace, [signature, fact], deps)
    return fact.fid


def upload_builder(node, workspace):
    """Spool direct-upload bytes outside the workspace/object-store answer."""
    from deploy.upload_journal import UploadSourceBuilder

    return UploadSourceBuilder(
        os.path.join(node.dir, "uploads"),
        workspace,
        node.member_for(workspace),
    )


def upload_source(
        node, workspace, source, broker_url, provider_origin):
    """Run the one provider-neutral direct uploader with a fresh auth proof."""
    from core.node import now_ms
    from deploy.upload_client_http import run_http
    import facts

    if source.workspace != workspace \
            or source.member != node.member_for(workspace):
        raise ValueError("upload source authority")

    def proof():
        now = now_ms()
        return node.sender(workspace).pack(facts.proof_payload(
            node, workspace, "upload", now + 120_000, now))

    result = run_http(source, broker_url, provider_origin, proof)
    return {
        "objects": result.object_count,
        "session": result.session,
        "upload": result.source_id,
    }
