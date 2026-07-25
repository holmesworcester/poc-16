"""Measure how key order changes multi-level range-sync cost.

All orders use the same facts, dependencies, and hash-derived treap shape.
``ts`` is production timestamp order, ``author`` groups by signing/device key,
and ``deleg`` groups each primary user's facts in delegation-DFS order. With
multi-device seeds, ``user`` additionally folds every roster device back into
that DFS user set. The delegation tree is reconstructed through
``user -> user_invite -> signer``; the invite's ephemeral invitee key is
deliberately never treated as the joined member.

Each depth row pulls the key range containing one real delegation subtree.
``tax`` is every multi-level fact fetched beyond that subtree's own facts.
Under DFS it should be path-bounded (roughly four auth facts per ancestor);
the scattered orders expose much larger ranges.
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tinyp2p.layout as L
from bench.bench_sync import WORK
from bench.seed_chain import SHAPES, build_seed
from tinyp2p import hoist as H
from tinyp2p.kernel import resolve_deps


def author_of(fact):
    pk = fact.body.get("pk")
    if pk:
        return pk
    for name, _, value in fact.offers():
        if name == "author":
            return value
    return "zz" + fact.fid[:8]


def closure(fids, deps_of):
    seen, stack = set(), list(fids)
    while stack:
        fid = stack.pop()
        if fid in seen:
            continue
        seen.add(fid)
        stack.extend(deps_of(fid))
    return seen


def leaves_of(root):
    leaves = []

    def visit(node):
        if node["leaf"]:
            leaves.append(node)
        else:
            visit(node["L"])
            visit(node["R"])

    visit(root)
    return leaves


def subtree_counts(root):
    """Map each layout node to ``(leaves, in-subtree facts, ancestor tax)``."""
    info = {}

    def visit(node, ancestor_facts):
        if node["leaf"]:
            leaves, inside = 1, node["n"]
        else:
            leaves, inside = 0, node["n"]
            for child in (node["L"], node["R"]):
                visit(child, ancestor_facts + node["n"])
                leaves += info[id(child)][0]
                inside += info[id(child)][1]
        info[id(node)] = (leaves, inside, ancestor_facts)

    visit(root, 0)
    return info


def delegation_topology(fids, fact_of):
    """Recover the enrolled-user tree and the DFS owner of every fact."""
    facts = {fid: fact_of(fid) for fid in fids}
    members = {
        fact.body["pk"]
        for fact in facts.values()
        if fact.t in {"workspace", "user"}
    }
    device_to_user = {member: member for member in members}
    for fact in facts.values():
        for name, user, device_key in fact.offers():
            if name != "device":
                continue
            previous = device_to_user.get(device_key)
            if previous is not None and previous != user:
                raise ValueError(f"device {device_key} belongs to two users")
            device_to_user[device_key] = user

    parent, invite_beneficiary = {}, {}
    for fid, fact in facts.items():
        if fact.t != "user":
            continue
        member = fact.body["pk"]
        invite_fid = fact.refs()[0][1]
        invitation = facts.get(invite_fid)
        if invitation is None or invitation.t != "user_invite":
            raise ValueError(f"user {fid} does not reference a user_invite")
        inviter_key = invitation.body["pk"]
        inviter = device_to_user.get(inviter_key, inviter_key)
        parent[member] = inviter
        invite_beneficiary[invite_fid] = member

    roots = sorted(members - set(parent))
    children = {}
    for child, inviter in parent.items():
        children.setdefault(inviter, []).append(child)
    for values in children.values():
        values.sort()

    dfs, depth = [], {}
    stack = [(root, 0) for root in reversed(roots)]
    while stack:
        member, member_depth = stack.pop()
        if member in depth:
            raise ValueError("delegation graph is not a tree")
        depth[member] = member_depth
        dfs.append(member)
        stack.extend(
            (child, member_depth + 1)
            for child in reversed(children.get(member, ()))
        )
    if set(dfs) != members:
        raise ValueError("delegation graph has unreachable members")

    descendants = {member: {member} for member in dfs}
    for member in reversed(dfs):
        inviter = parent.get(member)
        if inviter is not None:
            descendants[inviter].update(descendants[member])
    member_rank = {member: rank for rank, member in enumerate(dfs)}

    owner_cache = {}

    def owner_of(fid):
        if fid in owner_cache:
            return owner_cache[fid]
        fact = facts[fid]
        owner_cache[fid] = author_of(fact)
        if fact.t == "user_invite":
            owner_cache[fid] = invite_beneficiary.get(fid, owner_cache[fid])
        elif fact.t == "signature":
            target = fact.offers()[0][1]
            if target in facts:
                owner_cache[fid] = owner_of(target)
        return owner_cache[fid]

    owner_by_fact = {fid: owner_of(fid) for fid in fids}
    user_owner_by_fact = {
        fid: device_to_user.get(owner, owner)
        for fid, owner in owner_by_fact.items()
    }
    return {
        "parent": parent,
        "children": children,
        "roots": roots,
        "dfs": dfs,
        "depth": depth,
        "descendants": descendants,
        "member_rank": member_rank,
        "owner_by_fact": owner_by_fact,
        "user_owner_by_fact": user_owner_by_fact,
        "device_to_user": device_to_user,
        "invite_beneficiary": invite_beneficiary,
    }


def build_orders(fids, fact_of):
    facts = {fid: fact_of(fid) for fid in fids}
    topology = delegation_topology(fids, fact_of)
    timestamps = {fid: facts[fid].ts for fid in fids}
    member_rank = topology["member_rank"]
    owner_by_fact = topology["owner_by_fact"]
    user_owner_by_fact = topology["user_owner_by_fact"]

    def ranks(order_key):
        return {
            fid: rank
            for rank, fid in enumerate(sorted(fids, key=order_key))
        }

    return {
        "ts": ranks(lambda item: (timestamps[item], item)),
        "author": ranks(
            lambda item: (author_of(facts[item]), timestamps[item], item)),
        "deleg": ranks(lambda item: (
            member_rank.get(owner_by_fact[item], 1 << 30),
            timestamps[item],
            item,
        )),
        "user": ranks(lambda item: (
            member_rank.get(user_owner_by_fact[item], 1 << 30),
            timestamps[item],
            item,
        )),
    }, topology


def pick_targets(topology):
    """Pick comparable 1/small/large/full real delegation subtrees."""
    members = topology["dfs"]
    descendants = topology["descendants"]
    depth = topology["depth"]
    member_rank = topology["member_rank"]
    wanted = (1, max(2, len(members) // 10),
              max(4, len(members) // 2), len(members))
    picked = []
    for size in wanted:
        member = min(
            members,
            key=lambda item: (
                abs(len(descendants[item]) - size),
                -depth[item],
                member_rank[item],
            ),
        )
        if member not in picked:
            picked.append(member)
    return picked


def _payload_for_range(root, lo, hi):
    payload = set()

    def visit(node):
        if node["b"] <= lo or node["a"] >= hi:
            return
        payload.update(node["pay"])
        if not node["leaf"]:
            visit(node["L"])
            visit(node["R"])

    visit(root)
    return payload


def _delegation_row(target, topology, fids, positions, leaves,
                    leaf_closures, root):
    subtree_members = topology["descendants"][target]
    target_facts = {
        fid for fid in fids
        if topology["user_owner_by_fact"][fid] in subtree_members
    }
    lo = min(positions[fid] for fid in target_facts)
    hi = max(positions[fid] for fid in target_facts) + 1
    covered = [
        index for index, leaf in enumerate(leaves)
        if leaf["b"] > lo and leaf["a"] < hi
    ]
    range_lo = leaves[covered[0]]["a"]
    range_hi = leaves[covered[-1]]["b"]
    ml_facts = _payload_for_range(root, range_lo, range_hi)
    if not target_facts <= ml_facts:
        raise AssertionError("range path omitted target facts")
    leaf_only = sum(len(leaf_closures[index]) for index in covered)
    ml_total = len(ml_facts)
    return {
        "member": target,
        "depth": topology["depth"][target],
        "users": len(subtree_members),
        "leaves": len(covered),
        "target_facts": len(target_facts),
        "leaf_only": leaf_only,
        "tax": len(ml_facts - target_facts),
        "ml_total": ml_total,
        "lo_ml": leaf_only / ml_total if ml_total else 0,
    }


def measure(order, fids, fact_of, deps_of, rank, topology, targets=None):
    keys = [f"{rank[fid]:09d}:{fid}" for fid in fids]
    root, _ = H.build(keys, fact_of, deps_of)
    sorted_fids = sorted(fids, key=rank.get)
    positions = {fid: position for position, fid in enumerate(sorted_fids)}
    leaves = leaves_of(root)
    total_facts = len(fids)

    need_count = {}
    leaf_closures = []
    for leaf in leaves:
        closed = closure(sorted_fids[leaf["a"]:leaf["b"]], deps_of)
        leaf_closures.append(closed)
        for fid in closed:
            need_count[fid] = need_count.get(fid, 0) + 1
    leaf_total = sum(map(len, leaf_closures))
    page_count = len(leaves)

    info = subtree_counts(root)
    leaf_cost = {
        id(leaf): len(leaf_closures[index])
        for index, leaf in enumerate(leaves)
    }
    leaf_only_under = {}

    def annotate_leaf_only(node):
        if node["leaf"]:
            total = leaf_cost[id(node)]
        else:
            total = annotate_leaf_only(node["L"]) \
                + annotate_leaf_only(node["R"])
        leaf_only_under[id(node)] = total
        return total

    annotate_leaf_only(root)
    over_num = over_den = 0
    half = 0
    for node in H.walk(root):
        ride = info[id(node)][0]
        if ride * 2 >= page_count:
            half += len(node["pay"])
        for fid in node["pay"]:
            needed = need_count.get(fid, 1)
            over_den += ride
            over_num += ride - needed

    crossover = None
    for node in H.walk(root):
        node_leaves, inside, ancestor = info[id(node)]
        leaf_only = leaf_only_under[id(node)]
        if leaf_only >= inside + ancestor:
            crossover = node_leaves if crossover is None \
                else min(crossover, node_leaves)

    targets = targets or pick_targets(topology)
    rows = [
        _delegation_row(
            target, topology, fids, positions, leaves, leaf_closures, root)
        for target in targets
    ]
    mean_leaf_tax = sum(info[id(leaf)][2] for leaf in leaves) / page_count
    return {
        "order": order,
        "V": total_facts,
        "P": page_count,
        "rho": leaf_total / total_facts,
        "over": 100 * over_num / over_den,
        "mean_tax": mean_leaf_tax,
        "half": half,
        "crossover": crossover,
        "rows": rows,
    }


def benchmark(node_dir, scale, *, shape="random", n_members=100, seed=16,
              devices_per_user=1):
    seed_node, workspace, stats = build_seed(
        node_dir, scale, n_members=n_members, shape=shape, seed=seed,
        devices_per_user=devices_per_user)
    index = seed_node.idx(workspace)
    deps_cache = {}

    def fact_of(fid):
        return seed_node.fact_of(workspace, fid)

    def deps_of(fid):
        if fid not in deps_cache:
            deps_cache[fid] = resolve_deps(fact_of(fid), index) or []
        return deps_cache[fid]

    fids = [key.split(":", 1)[1] for key in seed_node.keys(workspace)]
    ranks, topology = build_orders(fids, fact_of)
    expected_parent = {
        member: inviter
        for member, inviter in stats["parents"].items()
        if inviter is not None
    }
    if topology["parent"] != expected_parent:
        raise AssertionError("reconstructed delegation parents differ from seed")
    if topology["depth"] != stats["depth_by_member"]:
        raise AssertionError("reconstructed delegation depths differ from seed")
    targets = pick_targets(topology)
    orders = ["ts", "author", "deleg"]
    if devices_per_user > 1:
        orders.append("user")
    results = {
        order: measure(
            order, fids, fact_of, deps_of, ranks[order], topology, targets)
        for order in orders
    }
    return seed_node, workspace, stats, topology, results


def _format_histogram(histogram):
    items = sorted(histogram.items())
    runs = []
    start_depth, previous_depth, count = items[0][0], items[0][0], items[0][1]
    for depth, next_count in items[1:]:
        if depth == previous_depth + 1 and next_count == count:
            previous_depth = depth
            continue
        label = str(start_depth) if start_depth == previous_depth \
            else f"{start_depth}-{previous_depth}"
        runs.append(f"{label}:{count}")
        start_depth = previous_depth = depth
        count = next_count
    label = str(start_depth) if start_depth == previous_depth \
        else f"{start_depth}-{previous_depth}"
    runs.append(f"{label}:{count}")
    return " ".join(runs)


def print_results(stats, results):
    depth = stats["depth"]
    print(
        f"\n=== {stats['shape']}  V={stats['facts']}  users={stats['members']}  "
        f"devices/user={stats['devices_per_user']}  "
        f"depth min/median/max={depth['min']}/{depth['median']:g}/{depth['max']} ===")
    print("    depth histogram (depth:users): "
          + _format_histogram(depth["histogram"]))
    orders = ["ts", "author", "deleg"]
    if stats["devices_per_user"] > 1:
        orders.append("user")
    for order in orders:
        result = results[order]
        print(
            f"\n[{order:6}] P={result['P']:5}  "
            f"leaf-only rho={result['rho']:.2f}x  ML full-sync=1.00x  "
            f"mean leaf tax={result['mean_tax']:.1f}  "
            f"facts >=50%={result['half']}  "
            f"crossover~{result['crossover']} leaves  "
            f"over-inclusion={result['over']:.1f}%")
        print(
            "         {:>5} {:>5} {:>7} {:>8} {:>9} {:>7} {:>9} {:>8}".format(
                "depth", "users", "leaves", "target", "LO_facts", "tax",
                "ML_total", "LO/ML"))
        for row in result["rows"]:
            print(
                "         {depth:5d} {users:5d} {leaves:7d} "
                "{target_facts:8d} {leaf_only:9d} {tax:7d} "
                "{ml_total:9d} {lo_ml:7.2f}x".format(**row))


def main():
    scale = next(
        (int(argument) for argument in sys.argv[1:] if argument.isdigit()),
        50000,
    )
    shapes = [argument for argument in sys.argv[1:] if argument in SHAPES]
    shapes = shapes or list(SHAPES)
    devices_per_user = next(
        (int(argument.split("=", 1)[1]) for argument in sys.argv[1:]
         if argument.startswith("devices=")),
        1,
    )
    old_cold_cut = L.COLD_CUT
    L.COLD_CUT = None
    try:
        for shape in shapes:
            directory = os.path.join(WORK, f"order_{shape}_{scale}")
            shutil.rmtree(directory, ignore_errors=True)
            _, _, stats, _, results = benchmark(
                os.path.join(directory, "seed"), scale, shape=shape,
                devices_per_user=devices_per_user)
            print_results(stats, results)
            shutil.rmtree(directory, ignore_errors=True)
    finally:
        L.COLD_CUT = old_cold_cut


if __name__ == "__main__":
    main()
