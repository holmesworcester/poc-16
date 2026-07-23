"""The kernel: one streaming judge for content, auth, and access.

kernel(stream, anchor)            -> (ok, valids, new_globals)   # drain
kernel(stream, anchor, globals_)  -> same, ephemeral checks on   # evaluate

A pure predicate over a fully closed unit: zero store reads, its own SQLite
scratchpad per invocation (caller may inject a connection), one forward pass.
The whole streaming contract is the seen-set rule — every ref resolves and
every need matches an offer already behind the cursor, or the unit rejects
(all-or-nothing). Integrity (fid == hash of canonical bytes) is enforced at
the decode boundary (fact.from_json); in-process Facts carry it by
construction. Only ephemeral families ever read globals_.

Valid is constructed here and nowhere else; projectors consume it blindly.
"""
import sqlite3
from typing import NamedTuple

from .crypto import verify
from .fact import Fact, presig

SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(fid TEXT PRIMARY KEY, ts INT, t TEXT);
CREATE TABLE IF NOT EXISTS offers(name TEXT, a0 TEXT, a1 TEXT, src TEXT,
                                  PRIMARY KEY(name, a0, a1, src));
"""

EPHEMERAL = {"req"}  # judged, never merged: the set must not grow with reads

ALLOWED = {  # offer names a family may emit — anything else rejects
    "genesis": {"member", "admin"}, "sig": {"author"}, "invite": {"invitee"},
    "join": {"member"}, "evict": {"removed"}, "msg": set(), "file": set(), "req": set(),
}


class Valid(NamedTuple):
    fact: Fact
    deps: tuple  # provider fids: refs + resolved need providers, canonical


def offer_src(db, name, a0, a1=None):
    """Canonical provider (min src) for an offer address, or None."""
    q, args = "SELECT src FROM offers WHERE name=? AND a0=?", [name, a0]
    if a1 is not None:
        q, args = q + " AND a1=?", args + [a1]
    row = db.execute(q + " ORDER BY src LIMIT 1", args).fetchone()
    return row and row[0]


def resolve_deps(f: Fact, db):
    """The fact's needs, resolved to canonical providers. None = unmet.

    Shared by the kernel (satisfaction check) and the layout/closer (the same
    resolution against the cumulative index gives canonical dep edges).
    """
    deps = [fid for _, fid in f.refs()]
    if f.t in ("genesis", "sig"):
        return deps
    pk = f.body.get("pk", "")
    a = offer_src(db, "author", f.fid, pk)  # my declared pk signed my fid
    if not a:
        return None
    deps.append(a)
    if f.t == "join":  # entitlement is the ref'd invite, not membership
        return deps
    m = offer_src(db, "admin" if f.t in ("invite", "evict") else "member", pk)
    if not m:
        return None
    deps.append(m)
    return deps


# ---- family validators: check atoms, return boolean --------------------------

def v_genesis(f, db, anchor, g):
    pk = f.body.get("pk", "")
    return (f.fid == anchor
            and f.atoms == [["offer", "member", pk], ["offer", "admin", pk]]
            and verify(pk, presig("genesis", f.ts, f.atoms), f.body["sig"]))


def v_sig(f, db, anchor, g):
    if len(f.offers()) != 1:
        return False
    (_, target, pk), = f.offers()
    return verify(pk, target, f.body["sig"])


def v_invite(f, db, anchor, g):
    return len(f.offers()) == 1


def v_join(f, db, anchor, g):
    if len(f.refs()) != 1 or f.offers() != [("member", f.body.get("pk", ""), "")]:
        return False
    row = db.execute("SELECT a0 FROM offers WHERE name='invitee' AND src=?",
                     (f.refs()[0][1],)).fetchone()
    return bool(row) and verify(row[0], f.body["pk"], f.body["countersig"])


def v_req(f, db, anchor, g):
    return g is None or f.body.get("pk", "") not in g


def v_plain(f, db, anchor, g):
    return True


VALIDATORS = {"genesis": v_genesis, "sig": v_sig, "invite": v_invite, "join": v_join,
              "evict": v_plain, "msg": v_plain, "file": v_plain, "req": v_req}


# ---- the judge ---------------------------------------------------------------

def kernel(stream, anchor, globals_=None, db=None):
    con = db or sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    con.execute("BEGIN")
    valids, removed = [], set()
    for f in stream:
        if con.execute("SELECT 1 FROM facts WHERE fid=?", (f.fid,)).fetchone():
            continue  # dedup by fid — free, and what keeps validation stateless
        try:
            ok = (f.t in VALIDATORS
                  and all(name in ALLOWED[f.t] for name, _, _ in f.offers())
                  and all(con.execute("SELECT 1 FROM facts WHERE fid=?", (rfid,)).fetchone()
                          for _, rfid in f.refs()))  # the seen-set rule
            deps = resolve_deps(f, con) if ok else None
            good = deps is not None and VALIDATORS[f.t](f, con, anchor, globals_)
        except Exception:
            good = False  # a fact that crashes the judge is a reject, never poison
        if not good:
            con.rollback()
            return False, [], set()  # all-or-nothing: the unit rejects whole
        con.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?)", (f.fid, f.ts, f.t))
        for name, a0, a1 in f.offers():
            con.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)", (name, a0, a1, f.fid))
            if name == "removed":
                removed.add(a0)
        valids.append(Valid(f, tuple(deps)))
    con.commit()
    if db is None:
        con.close()
    return True, valids, removed
