"""Build benchmark seeds with real multi-hop delegation trees.

The four shapes keep the authority facts identical and vary only who invites
each user: ``star`` is the old founder-only low bar, ``wide`` models a small
set of prolific inviters, ``random`` is a uniform random recursive tree, and
``chain`` is the adversarial spine. Membership and content are bulk-inserted;
the finished fact set receives one layout commit.
"""
import collections
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.bench_sync import MEMBERS, YEARS, _insert, bulk_author
from tinyp2p import cmds
from tinyp2p.crypto import keypair
from tinyp2p.facts.auth.device import device
from tinyp2p.facts.auth.device_invite import device_invite
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.node import Node

SHAPES = ("star", "wide", "random", "chain")


def _parent_index(shape, ordinal, rng, wide_inviters):
    """Choose an existing member for the user at one-based ``ordinal``."""
    if shape == "star":
        return 0
    if shape == "chain":
        return ordinal - 1
    if shape == "random":
        return rng.randrange(ordinal)
    if ordinal <= wide_inviters:
        return 0
    return 1 + (ordinal - wide_inviters - 1) % wide_inviters


def _depth_stats(depths):
    histogram = dict(sorted(collections.Counter(depths).items()))
    return {
        "histogram": histogram,
        "min": min(depths),
        "median": statistics.median(depths),
        "max": max(depths),
    }


def grow_tree(node, workspace, n_members, base_ts, rng, *,
              shape="random", wide_inviters=8):
    """Bulk-build a delegation tree and return identities plus its topology."""
    if shape not in SHAPES:
        raise ValueError(f"shape must be one of {SHAPES}, got {shape!r}")
    if n_members < 1:
        raise ValueError("n_members must include at least the founder")
    if wide_inviters < 1:
        raise ValueError("wide_inviters must be positive")

    identities = [(node.sk, node.pk)]
    parents = {node.pk: None}
    depths = {node.pk: 0}
    users = {node.pk: workspace}
    idx = node.idx(workspace)
    idx.execute("BEGIN")
    try:
        for ordinal in range(1, n_members):
            parent_at = _parent_index(
                shape, ordinal, rng, min(wide_inviters, ordinal))
            inviter_sk, inviter_pk = identities[parent_at]
            invite_ts = base_ts + 2 * ordinal - 1
            user_ts = invite_ts + 1

            invite_sk, invite_pk = keypair()
            invitation = user_invite(inviter_pk, invite_pk, invite_ts)
            invitation_sig = signature(
                inviter_sk, inviter_pk, invitation, invite_ts)
            member_sk, member_pk = keypair()
            joined = user(
                invitation, invite_sk, member_pk, f"u{ordinal - 1}", user_ts)
            joined_sig = signature(member_sk, member_pk, joined, user_ts)

            for fact in (invitation_sig, invitation, joined_sig, joined):
                _insert(idx, fact)
            node.keychain.add_identity(member_sk, persist=False)
            identities.append((member_sk, member_pk))
            parents[member_pk] = inviter_pk
            depths[member_pk] = depths[inviter_pk] + 1
            users[member_pk] = joined.fid
        idx.commit()
        node.keychain.save()
    except Exception:
        idx.rollback()
        raise
    return identities, parents, depths, users


def grow_devices(node, workspace, identities, base_ts, devices_per_user):
    """Bulk-build equal-peer device sets and return all author identities."""
    if devices_per_user < 2:
        raise ValueError("grow_devices requires more than one device per user")
    all_devices = []
    devices_by_user = {}
    device_to_user = {}
    idx = node.idx(workspace)
    idx.execute("BEGIN")
    try:
        ts = base_ts
        for user_number, (user_secret, user_public) in enumerate(identities):
            primary = device(user_public, f"u{user_number}-d0", ts)
            primary_sig = signature(
                user_secret, user_public, primary, ts)
            _insert(idx, primary_sig)
            _insert(idx, primary)
            device_set = [(user_secret, user_public)]
            devices_by_user[user_public] = [user_public]
            device_to_user[user_public] = user_public
            ts += 1

            for device_number in range(1, devices_per_user):
                inviter_secret, inviter_public = device_set[-1]
                sibling_secret, sibling_public = keypair()
                grant = device_invite(
                    inviter_public, user_public, sibling_public,
                    f"u{user_number}-d{device_number}", ts)
                grant_sig = signature(
                    inviter_secret, inviter_public, grant, ts)
                _insert(idx, grant_sig)
                _insert(idx, grant)
                node.keychain.add_identity(sibling_secret, persist=False)
                device_set.append((sibling_secret, sibling_public))
                devices_by_user[user_public].append(sibling_public)
                device_to_user[sibling_public] = user_public
                ts += 1
            all_devices.extend(device_set)
        idx.commit()
        node.keychain.save()
    except Exception:
        idx.rollback()
        raise
    return all_devices, devices_by_user, device_to_user


def build_seed(node_dir, total_facts, n_members=MEMBERS, years=YEARS, seed=16,
               shape="random", wide_inviters=8, devices_per_user=1):
    """Return ``(node, workspace, stats)`` for a measured delegation shape."""
    if devices_per_user < 1:
        raise ValueError("devices_per_user must be positive")
    rng = random.Random(seed)
    node = Node(node_dir)
    started = time.perf_counter()
    workspace = cmds.create(node, "alice")
    root_ts = node.fact_of(workspace, workspace).ts
    identities, parents, depths, users = grow_tree(
        node, workspace, n_members, root_ts + 1, rng,
        shape=shape, wide_inviters=wide_inviters)
    devices_by_user = {
        public: [public] for _, public in identities
    }
    device_to_user = {
        public: public for _, public in identities
    }
    content_identities = identities
    if devices_per_user > 1:
        first_device_ts = node.idx(workspace).execute(
            "SELECT MAX(ts) FROM facts").fetchone()[0] + 1
        content_identities, devices_by_user, device_to_user = grow_devices(
            node, workspace, identities, first_device_ts, devices_per_user)
    membership_done = time.perf_counter()

    membership_facts = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    n_messages = max(0, (total_facts - membership_facts) // 2)
    window = years * 365 * 24 * 3600 * 1000
    content_ts = node.idx(workspace).execute(
        "SELECT MAX(ts) FROM facts").fetchone()[0] + 1
    bulk_author(
        node, workspace, content_identities, n_messages,
        content_ts, window, rng)
    authored = time.perf_counter()
    node.commit(workspace)
    finished = time.perf_counter()

    total = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    depth = _depth_stats(list(depths.values()))
    stats = {
        "shape": shape,
        "seed": seed,
        "members": n_members,
        "messages": n_messages,
        "facts": total,
        "parents": parents,
        "depth_by_member": depths,
        "user_by_member": users,
        "devices_per_user": devices_per_user,
        "devices_by_user": devices_by_user,
        "device_to_user": device_to_user,
        "depth": depth,
        "membership_s": membership_done - started,
        "author_s": authored - membership_done,
        "layout_s": finished - authored,
        "setup_s": finished - started,
    }
    return node, workspace, stats
