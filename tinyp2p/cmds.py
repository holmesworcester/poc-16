"""Commands: the command => fact patterns. Each authors facts through the
family authors, closes them into a pile in its own ingress, runs a turn,
and kicks the syncer — eager delivery, with the walk as backstop."""
import base64
import json
import os
import urllib.request

from . import fact as F
from .close import close, decode_pile, encode_pile
from .crypto import box_decrypt, box_encrypt, h, kdf, keypair, load_sk
from .kernel import resolve_deps
from .node import now_ms
from .walk import walk


def _closer(node, ws, newmap, deps):
    fact_of = lambda fid: newmap.get(fid) or node.fact_of(ws, fid)
    deps_of = lambda fid: deps[fid] if fid in deps else \
        (resolve_deps(fact_of(fid), node.idx(ws)) or [])
    return close(list(newmap.values()), deps_of, fact_of)


def _publish(node, ws, f, s, role="member", blobs=None):
    """Content-fact tail: deps = refs + my sig + my chain; pile; turn."""
    with node.lock:
        src = node.member_src(ws, role)
    deps = {f.fid: [r for _, r in f.refs()] + [s.fid] + ([src] if src else []),
            s.fid: []}
    node.ingest_new(ws, [s, f], deps, blobs)
    return f.fid


def create(node, name):
    g = F.genesis(node.sk, node.pk, name, now_ms())
    ws = g.fid  # workspace id == anchor == genesis fid
    node.keyring["workspaces"][ws] = {"peers": [], "name": name}
    node.save_keyring()
    node.ingest_new(ws, [g], {g.fid: []})
    return ws


def make_invite(node, ws):
    """Invite blob: a closed pile + the invite secret, encrypted under the
    link seed, at a public unguessable id. Not merged into the treap —
    unclaimed invites stay revocable by delete."""
    seed = os.urandom(32)
    isk, ipk = keypair()
    ts = now_ms()
    inv = F.invite(node.pk, ipk, ts)
    s = F.sig_for(node.sk, node.pk, inv, ts)
    with node.lock:
        asrc = node.member_src(ws, "admin")
        facts = _closer(node, ws, {s.fid: s, inv.fid: inv},
                        {inv.fid: [s.fid, asrc], s.fid: []})
    blob = F.canon({"pile": [x.to_json() for x in facts],
                    "isk": isk.encode().hex(), "ws": ws})
    node.store(ws).put("invite/" + kdf(seed, "id").hex(),
                       box_encrypt(kdf(seed, "key"), blob))
    return base64.urlsafe_b64encode(
        F.canon({"u": node.url, "ws": ws, "s": seed.hex()})).decode()


def join(node, link, name):
    """Redemption is self-contained: the blob carries the invite fact and its
    full admin closure, so the join pile proves itself everywhere."""
    o = json.loads(base64.urlsafe_b64decode(link))
    url, ws, seed = o["u"], o["ws"], bytes.fromhex(o["s"])
    enc = urllib.request.urlopen(
        f"{url}/invite/{kdf(seed, 'id').hex()}?ws={ws}", timeout=15).read()
    blob = json.loads(box_decrypt(kdf(seed, "key"), enc))
    bfacts = [F.from_json(x) for x in blob["pile"]]
    inv = [f for f in bfacts if f.t == "invite"][-1]
    ts = now_ms()
    j = F.join(inv, load_sk(blob["isk"]), node.pk, name, ts)
    s = F.sig_for(node.sk, node.pk, j, ts)
    node.keyring["workspaces"][ws] = {"peers": [url], "name": name}
    node.save_keyring()
    b = encode_pile(bfacts + [s, j])  # blob is closed and topo; append news
    node.store(ws).put(f"pile/{node.member}/{h(b)}", b)
    node.turn(ws)
    walk(node, ws, url)  # push the join, pull the world
    return ws


def post(node, ws, chan, text, ts=None):
    ts = ts or now_ms()  # explicit old ts = a straggler (test hook)
    f = F.msg(node.pk, chan, text, ts)
    return _publish(node, ws, f, F.sig_for(node.sk, node.pk, f, ts))


def send_file(node, ws, chan, name, data: bytes):
    """Files are standalone blobs of any size; the fact carries the ref."""
    ts = now_ms()
    bh = h(data)
    f = F.file_fact(node.pk, chan, name, len(data), bh, ts)
    return _publish(node, ws, f, F.sig_for(node.sk, node.pk, f, ts),
                    blobs={bh: data})


def evict(node, ws, target):
    with node.lock:
        row = node.app.execute(
            "SELECT pk FROM members WHERE ws=? AND (pk=? OR name=?)",
            (ws, target, target)).fetchone()
    if not row:
        raise ValueError(f"no member {target!r}")
    ts = now_ms()
    f = F.evict(node.pk, row[0], ts)
    return _publish(node, ws, f, F.sig_for(node.sk, node.pk, f, ts), role="admin")


# ---- read-model queries ------------------------------------------------------

def msgs(node, ws, chan=None):
    q = "SELECT chan, pk, text, ts, fid FROM messages WHERE ws=?" + \
        (" AND chan=?" if chan else "") + " ORDER BY ts, fid"
    with node.lock:
        rows = node.app.execute(q, (ws, chan) if chan else (ws,)).fetchall()
        names = dict(node.app.execute("SELECT pk, name FROM members WHERE ws=?", (ws,)))
    return [{"chan": c, "from": names.get(pk, pk[:8]), "text": t, "ts": ts, "fid": fid}
            for c, pk, t, ts, fid in rows]


def members(node, ws):
    with node.lock:
        rows = node.app.execute(
            "SELECT pk, name, role, evicted FROM members WHERE ws=? ORDER BY name",
            (ws,)).fetchall()
    return [{"pk": pk, "name": n, "role": r, "evicted": bool(e)} for pk, n, r, e in rows]


def files(node, ws):
    with node.lock:
        rows = node.app.execute(
            "SELECT fid, chan, name, size, blob, ts FROM files WHERE ws=? ORDER BY ts",
            (ws,)).fetchall()
    return [{"fid": f, "chan": c, "name": n, "size": s, "blob": b, "ts": ts}
            for f, c, n, s, b, ts in rows]


def file_bytes(node, ws, fid):
    with node.lock:
        row = node.app.execute("SELECT name, blob FROM files WHERE ws=? AND fid=?",
                               (ws, fid)).fetchone()
    if not row:
        return None
    return row[0], node.store(ws).get("obj/" + row[1])


def status(node):
    out = {"pk": node.pk, "member": node.member, "workspaces": {}}
    with node.lock:
        for ws, entry in node.keyring["workspaces"].items():
            out["workspaces"][ws] = {
                "root": node.store(ws).etag("root"),
                "facts": node.idx(ws).execute("SELECT COUNT(*) FROM facts").fetchone()[0],
                "peers": entry["peers"], "name": entry["name"]}
    return out
