"""Repository boundaries are executable, not naming conventions."""
import ast
import hashlib
import json
import re
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ROOT_DOCS = {"AGENTS.md", "DESIGN.md", "README.md"}
RECOVERY_EPIC = "poc-16-kb6"
BANKRUPTCY_REASON = (
    "Bead bankruptcy 2026-07-27: superseded by docs/TODO.md and replacement "
    "epic poc-16-kb6. Closed history is preserved; no requirement survives "
    "unless restated under poc-16-kb6."
)
BANKRUPTCY_RETIRED_IDS = frozenset("""
poc-16-0ow
poc-16-3fq
poc-16-3tg
poc-16-7iy
poc-16-8lq
poc-16-92v
poc-16-92v.1
poc-16-92v.2
poc-16-92v.3
poc-16-92v.4
poc-16-92v.5
poc-16-92v.6
poc-16-92v.7
poc-16-9fc
poc-16-9fc.1
poc-16-9fc.10
poc-16-9fc.2
poc-16-9fc.3
poc-16-9fc.4
poc-16-9fc.5
poc-16-9fc.6
poc-16-9fc.7
poc-16-9fc.8
poc-16-9fc.9
poc-16-gev
poc-16-gxz
poc-16-jbg
poc-16-jbg.2
poc-16-jbg.3
poc-16-jbg.4
poc-16-jbg.5
poc-16-jbg.6
poc-16-jbg.7
poc-16-jbg.8
poc-16-jbg.9
poc-16-nto
poc-16-t9f
poc-16-t9f.1
poc-16-t9f.2
poc-16-t9f.3
poc-16-t9f.4
poc-16-up4
poc-16-x1o
poc-16-x1o.10
poc-16-x1o.11
poc-16-x1o.12
poc-16-x1o.13
poc-16-x1o.14
poc-16-x1o.15
poc-16-x1o.16
poc-16-x1o.17
poc-16-x1o.18
poc-16-x1o.19
poc-16-x1o.2
poc-16-x1o.20
poc-16-x1o.21
poc-16-x1o.22
poc-16-x1o.23
poc-16-x1o.24
poc-16-x1o.25
poc-16-x1o.26
poc-16-x1o.27
poc-16-x1o.4
poc-16-x1o.5
poc-16-x1o.6
poc-16-x1o.7
poc-16-x1o.8
poc-16-x1o.9
poc-16-yez
poc-16-yez.11
poc-16-yez.12
poc-16-yez.14
poc-16-yez.5
poc-16-yez.7
poc-16-yez.8
poc-16-yez.9
""".split())
RECOVERY_ISSUES = {
    RECOVERY_EPIC,
    *(f"{RECOVERY_EPIC}.{number}" for number in range(1, 12)),
}
RECOVERY_BLOCKERS = {
    f"{RECOVERY_EPIC}.2": {f"{RECOVERY_EPIC}.4"},
    f"{RECOVERY_EPIC}.5": {f"{RECOVERY_EPIC}.2"},
    f"{RECOVERY_EPIC}.6": {f"{RECOVERY_EPIC}.5"},
    f"{RECOVERY_EPIC}.7": {f"{RECOVERY_EPIC}.6"},
    f"{RECOVERY_EPIC}.9": {f"{RECOVERY_EPIC}.5"},
    f"{RECOVERY_EPIC}.10": {
        f"{RECOVERY_EPIC}.3",
        f"{RECOVERY_EPIC}.6",
        f"{RECOVERY_EPIC}.7",
        f"{RECOVERY_EPIC}.8",
        f"{RECOVERY_EPIC}.9",
    },
    f"{RECOVERY_EPIC}.11": {f"{RECOVERY_EPIC}.10"},
}
LINK = re.compile(r"\[[^]]*]\(([^)]+)\)")
OLD_REFERENCE = re.compile(
    r"(?<!docs/)(?:SIMPLIFY|DELETION_CLOSURE|MODEL|WORKSPACES|"
    r"MULTILEVEL_PILE|CHAINED_AUTH_PLAN|IMPLEMENTATION|TREAP_PROTOTYPE)\.md"
    r"|tinyp2p(?:/|\.)"
    r"|(?<![A-Za-z0-9_./-])(?:tree|layout|hoist|shape|sync|walk|kernel|node|"
    r"mint|pump|fact|store|close|cmds|cli|daemon|keychain|suppression|treap)"
    r"\.py"
)


def test_only_entrypoint_docs_live_at_root():
    assert {path.name for path in ROOT.glob("*.md")} == ROOT_DOCS
    assert not (ROOT / "tinyp2p").exists()
    assert (ROOT / "core" / "__init__.py").is_file()
    assert (ROOT / "facts" / "__init__.py").is_file()
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "**SETTLED:** `AGENTS.md` survives" in ledger
    assert "**OPEN:** whether AGENTS.md survives" not in ledger


def test_python_imports_do_not_restore_the_old_namespace():
    for directory in ("core", "facts", "tests", "bench"):
        for path in (ROOT / directory).rglob("*.py"):
            tree = ast.parse(path.read_text())
            package_depth = len(path.relative_to(ROOT).parts) - 1
            assert all(
                node.level <= package_depth
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            ), path
            names = [
                node.module for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            ] + [
                alias.name for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names
            ]
            assert not any(
                name == "tinyp2p" or name.startswith("tinyp2p.")
                for name in names if name
            ), path


def test_local_document_links_resolve():
    documents = list(ROOT.glob("*.md")) + list((ROOT / "docs").glob("*.md"))
    for document in documents:
        for target in LINK.findall(document.read_text()):
            path = urllib.parse.unquote(target.split("#", 1)[0])
            if path and "://" not in path and not path.startswith("mailto:"):
                assert (document.parent / path).exists(), (document, target)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def exported_beads():
    return [
        json.loads(line)
        for line in (ROOT / ".beads" / "issues.jsonl").read_text().splitlines()
    ]


def test_active_exported_beads_use_current_paths():
    """Closed bead prose is history; only the executable frontier is routing."""
    for issue in exported_beads():
        if issue["status"] == "closed":
            continue
        text = "\n".join(strings(issue))
        assert not OLD_REFERENCE.search(text), issue["id"]


def test_active_exported_beads_belong_to_the_bankruptcy_recovery_epic():
    """The old graph cannot silently re-enter bd ready after bankruptcy."""
    active = [issue for issue in exported_beads()
              if issue["status"] != "closed"]
    active_ids = {issue["id"] for issue in active}
    assert RECOVERY_EPIC in active_ids
    assert active_ids <= RECOVERY_ISSUES
    assert all(
        issue["id"] == RECOVERY_EPIC
        or any(
            dependency["type"] == "parent-child"
            and dependency["depends_on_id"] == RECOVERY_EPIC
            for dependency in issue.get("dependencies", ())
        )
        for issue in active
    )


def test_recovery_epic_is_claimed_until_s10():
    """The coordination epic cannot masquerade as executable frontier work."""
    issues = {issue["id"]: issue for issue in exported_beads()}
    epic = issues[RECOVERY_EPIC]

    assert epic["status"] == "in_progress"
    assert epic.get("assignee")
    assert "unclaimed-recovery-epic" in (
        ROOT / "docs" / "TODO.md"
    ).read_text()


def test_bankruptcy_export_preserves_the_live_dolt_declaration_snapshot():
    """The exact retired set came from live Dolt, not the stale prior export."""
    retired = [
        issue for issue in exported_beads()
        if issue.get("close_reason") == BANKRUPTCY_REASON
    ]
    retired_ids = {issue["id"] for issue in retired}
    assert len(retired) == len(retired_ids)
    assert retired_ids == BANKRUPTCY_RETIRED_IDS


def test_recovery_bead_specs_resolve_to_the_bankruptcy_ledger():
    """Every executable replacement points back to an existing plan section."""
    issues = {issue["id"]: issue for issue in exported_beads()}
    assert RECOVERY_ISSUES <= issues.keys()
    for issue_id in RECOVERY_ISSUES:
        spec, _, anchor = issues[issue_id]["spec_id"].partition("#")
        document = ROOT / spec
        assert document == ROOT / "docs" / "TODO.md"
        assert document.is_file()
        if anchor:
            headings = {
                re.sub(r"[^\w -]", "", line.lstrip("# ").lower()).replace(
                    " ", "-"
                )
                for line in document.read_text().splitlines()
                if line.startswith("#")
            }
            assert anchor in headings, issue_id


def test_recovery_dependency_graph_matches_the_ledger():
    """Bankrupt dependencies cannot leak back into the replacement ordering."""
    issues = {issue["id"]: issue for issue in exported_beads()}
    for issue_id in RECOVERY_ISSUES - {RECOVERY_EPIC}:
        blockers = {
            dependency["depends_on_id"]
            for dependency in issues[issue_id].get("dependencies", ())
            if dependency["type"] == "blocks"
        }
        assert blockers == RECOVERY_BLOCKERS.get(issue_id, set()), issue_id


def test_recovery_beads_own_the_safe_storage_transition():
    """Review-found cutover invariants must survive outside temporary prose."""
    issues = {issue["id"]: issue for issue in exported_beads()}
    epic = "\n".join(strings(issues[RECOVERY_EPIC]))
    s0 = "\n".join(strings(issues[f"{RECOVERY_EPIC}.1"]))
    s1 = "\n".join(strings(issues[f"{RECOVERY_EPIC}.3"]))
    s2 = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    s4 = "\n".join(strings(issues[f"{RECOVERY_EPIC}.5"]))
    s5 = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    performance = "\n".join(strings(issues[f"{RECOVERY_EPIC}.9"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    assert "oversized message" in s4
    assert "raw-fact chunks" in s4
    assert "without changing its fid" in s4
    assert "workspace-global" in s5
    assert "LEGACY_SLOT" in s5
    assert "LEGACY_GLOBAL" in s5
    assert "grandfather receipt" in s5
    assert "removal global" in s5
    assert "later evicted" in s5
    assert "different basis roots" in s5
    assert "frontier/<workspace>" in s5
    assert "pre-eviction basis" in s5
    assert "fenced and must reseed" in s5
    assert "service-exclusive" in s5
    assert "workspace.body.pk" in s5
    assert "retained quarantine" in s5
    assert "prospective" in s5
    assert "InclusionWitness" in s5
    assert "served-authority" in s5
    assert "MemberPrincipal" in s5
    assert "LegacyMask" in s5
    assert "pending/" in s5
    assert "TargetRegistry" in s5
    assert "LegacyAuthorityCheckpoint" in s5
    assert "RevocationLiability" in s5
    assert "zero-provider" in s5
    assert "AuthorityImpactRegistry" in s4
    assert "AuthorityImpactRegistry" in s5
    assert "AuthorityCandidateRegistry" in s4
    assert "AuthorityCandidateRegistry" in s5
    assert "cutover_basis_digest" in s5
    assert "TargetRegistry row and byte escrow" in s5
    assert "4,096 examined candidate refs" in \
        "\n".join(strings(issues[f"{RECOVERY_EPIC}.9"]))
    assert "Cutover-cycle mutation" in \
        "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))
    assert "Target-row-byte" in \
        "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))
    assert "AttemptWriteLease" in s5
    assert "fixed scratch" in s5
    assert "DevicePrincipal" in s5
    assert "canonical SuppSlot witnesses" in s4
    assert "FactRecord/raw-chunk objects and bytes" in s5
    assert "admit-cell byte reserve" in s4
    assert "migration-seal object/byte reserve" in s4
    assert "Every admit cell reserves exact bytes" in s5
    assert "At most 7 proposal/support proof refs plus the service-derived " \
        "ActionAuthorization determine proof_digest" in s5
    assert "full-size admit-cell bytes" in \
        "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))
    assert "Receipt-cycle mutation" in \
        integration
    assert "exact 80-byte canonical door" in epic
    assert "LegacyIamAttestation" in epic
    assert "served cell and inclusion witness" in epic
    assert "FACT_TS_MAX" in s1
    assert "16-digit-positive" in s1
    assert "MAX_LEGACY_IAM_ATTESTATION_BYTES" in s2
    assert "served-cell/inclusion-witness row-and-byte" in s2
    assert "maximum legal 80-byte keys" in s4
    assert "definitively drains every accepted or ambiguous pre-fence write" \
        in s5
    assert "PublisherCapacityCell" in s5
    assert "prepares only its publishing deployment" in s5
    assert "exact 80-byte target/evidence keys" in performance
    assert "no snapshot/seal precedes definitive drain" in integration
    assert "GC the retained LegacyIamAttestation" in integration
    assert "Capacity mutations independently exhaust served-cell" \
        in integration
    assert "PublisherCapacityCell" in integration
    assert "lexicographically lowest verified publisher origin" in epic
    assert "distinct normal Sid and LegacyMask Migration owner-slot shapes" \
        in s2
    assert "same lowest-origin row/digest" in s4
    assert "legal quarantine-only target" in s4
    assert "lowest verified publisher id before hashing" in s5
    assert "normal ActionSlot(Sid(resolved_sid)) and SuppSlot" in s5
    assert "first-seen-origin mutant" in integration
    assert "forced-LegacyMask mutant" in integration
    assert "pre-record legacy_mask_namespace" in epic
    assert "Migration(legacy_mask_namespace, victim_fid)" in s2
    assert "masked-FactRecord/cutover cycle mutant" in s4
    assert "LegacyMask derives only from the pre-record namespace" in s5
    assert "final-cutover-derived LegacyMask mutant" in integration
    assert "writable S4 abort generation" in epic
    assert "aggregate admission proof bytes" in s2
    assert "dual-scope later provider" in s2
    assert "explicit layout_seed root field" in s4
    assert "O(1) PublisherCapacityCell" in s4
    assert "prepared service-only S4 fallback" in s5
    assert "post-fence S4-stranding" in integration
    assert "overlarge-proof-bundle" in integration
    assert "first-typed-tombstone" in integration
    assert "AUTHORITY_LIVENESS_GUARDS" in s2
    assert "closure-wide-candidate-masking" in integration
    assert "CutoverServiceGeneration" in s2
    assert "workspace-sized-service-row-plan" in integration
    assert "CutoverCommitAnchor" in s2
    assert "root-bound-grandfather-row" in integration
    assert "principal-scope-does-not-mask-sid-guard" in integration
    assert "DirectCommitPair" in s2
    assert "live-root-only-direct-proof-regeneration" in integration
    assert "request.VERBS" in s4
    assert "skip-ephemeral-family-gate" in integration
    assert "Review closure 17" in s0
    assert "sorted_provider_sids" in epic
    assert "LegacyEffectCensus" in epic
    assert "WorkerReadLease" in epic
    assert "aggregate proof plus one 32 KiB receipt" in epic
    assert "mandatory sorted_provider_sids" in s2
    assert "eight full FactRecord envelopes" in s2
    assert "before hashing any migrated FactRecord" in s4
    assert "64 fixed WorkerReadLease slots" in s4
    assert "legacy_effect_census_oid/digest" in s5
    assert "concurrent advances cannot reclaim or mix" in s5
    assert "MAX_ADMISSION_PROOF_BYTES plus " \
        "MAX_REVOCATION_RECORD_RAW_BYTES" in performance
    assert "legacy-mask-authority-provider-stays-live" in integration
    assert "late-legacy-mask-selector" in integration
    assert "drop-reconciled-s4-root" in integration
    assert "served-cell-only-read-lease" in integration
    assert "unbound-read-token" in integration
    assert "per-record-max-raw-proof-liability" in integration
    assert "Review closure 18" in s0
    assert "target_fact_record_oid" in epic
    assert "post-seal certification" in epic
    assert "TargetBinding and PrincipalBinding include " \
        "target_fact_record_oid" in s2
    assert "LegacyTranslationAttestation" in s4
    assert "post-seal code deletes the S4 decoder" in s5
    assert "drop-target-record-after-quarantine" in integration
    assert "post-seal-s4-decoder-dependency" in integration
    assert "Review closure 19" in s0
    assert "PrincipalProviderBinding" in epic
    assert "capped PrincipalProviderBinding triples" in s2
    assert "provider binding across quarantine" in s4
    assert "sixty-fifth distinct provider" in s5
    assert "provider-registry binding bytes" in performance
    assert "principal-provider-bare-fid-after-quarantine" in integration
    assert "Review closure 20" in s0
    assert "AuthorityProofRecord" in epic
    assert "grow-only ADMITTED archive" in epic
    assert "AuthorityProofRecord caps exact fact bindings" in s2
    assert "rooted proof preimages" in s4
    assert "authority proof admission is immutable" in s5
    assert "restore eligibility from the exact current FactTree" in \
        "\n".join(strings(issues[f"{RECOVERY_EPIC}.8"]))
    assert "authority-proof object/bytes" in performance
    assert "bare-authority-proof-digest" in integration
    assert "drop-authority-proof-support-after-quarantine" in integration
    assert "drop-post-s5-quarantined-fact-from-facttree" in integration
    assert "Review closure 21" in s0
    assert "candidate id and canonical rank are derived after its oid" in epic
    assert "RequiredCoOffer is a sorted exact component of NeedKey" in s2
    assert "hash proof records before deriving candidate ids/ranks" in s4
    assert "preclassify every legacy removal disposition" in s4
    assert "first-S5 FactTree admits only ORDINARY legacy rows" in s5
    assert "same-provider alternate paths" in s5
    assert "authority-proof-candidate-id-cycle" in integration
    assert "needkey-drops-required-cooffers" in integration
    assert "admit-inert-legacy-removal" in integration
    assert "checkpoint-coalesces-proof-closures" in integration
    assert "paged LegacyAuthorityProofRecord" in epic
    assert "COOFFERS_MATCH or COOFFERS_MISMATCH" in s2
    assert "migration sizing retains every paged legacy authority proof" in s4
    assert "off-request certification replays all pages" in s5
    assert "519-hop checkpoint fixture spans capped legacy-proof pages" \
        in integration
    assert "Review closure 24" in s0
    assert "CommittedAuthorityProof" in s2
    assert "authority proof admission is immutable" in s5
    assert "DERIVED_LEGACY_RANK" in s4
    assert "RawFactContentCommit" in s4
    assert "RawFactContentCommit" in s5
    assert "reresolve-admitted-proof-against-current-winner" in integration
    assert "checkpoint-descendant-uses-transport-depth" in integration
    assert "inline-raw-fact-chunks-overflow-publication-attempt" in integration
    assert "Review closure 25" in s0
    assert "discovery-only" in s2
    assert "64-scope union" in s4
    assert "ContentCommitPin transitions PENDING to ROOTED" in s5
    assert "162 registry objects/44,630,016 bytes" in s2
    assert "reuse-base-rank-for-full-needkey" in integration
    assert "late-needkey-multiplies-candidate-scopes" in integration
    assert "sort-raw-manifest-by-chunk-oid" in integration
    assert "content-generation-in-canonical-commit" in integration
    assert "collect-sealed-content-before-metadata-cas" in integration


def test_recovery_ledger_uses_only_the_service_admission_key():
    """Founder signatures and canonical bare proposals cannot regain effects."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "anchor-signed admission" not in ledger
    assert "workspace-signed receipt" not in ledger
    assert "workspace.body.pk` is never accepted at this seam" in ledger
    assert "An unreceipted removal\nproposal in the S5 FactTree is a " \
        "certification error" in ledger


def test_recovery_ledger_rejects_orphan_admission_receipts():
    """Only a durably serialized admission may create suppression effects."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    assert "AdmissionCommitProof" in ledger
    assert re.search(
        r"receipt signature\s+by itself is not a registry source",
        ledger,
    )
    assert "validly signed candidate receipt orphaned by a crash or failed CAS" \
        in ledger
    assert "post-commit signer" in contracts
    assert "failed-CAS orphan receipt" in contracts
    assert "pre-CAS orphan remains inert forever" in cutover
    assert "post-CAS/pre-proof crash" in cutover
    assert "replayed after author eviction" in integration


def test_recovery_ledger_retains_direct_commit_and_ephemeral_gate_evidence():
    """Restart proof recovery and Worker mint retain their non-tree gates."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    shadow = "\n".join(strings(issues[f"{RECOVERY_EPIC}.5"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    assert "durable\n**DirectCommitPair**" in ledger
    assert "signs the stored\nrow plus `EMPTY`" in ledger
    assert "does not require the historical root object" in ledger
    assert "after the\nlive root advances, old root objects are collected" \
        in ledger
    assert "service-supplied trusted `(\"now\", now_ms)` value" in ledger
    assert "`verb in request.VERBS`" in ledger
    assert "`exp >= trusted_now`" in ledger
    assert "DirectCommitPair" in contracts
    assert "DirectCommitPair" in cutover
    assert "request.VERBS" in shadow
    assert "live-root-only-direct-proof-regeneration" in integration
    assert "skip-ephemeral-family-gate" in integration


def test_recovery_ledger_reserves_complete_nonredundant_revocations():
    """Terminal tombstones and detached signatures cannot lose their escrow."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    shadow = "\n".join(strings(issues[f"{RECOVERY_EPIC}.5"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    attempt = ledger.index("durably claims the exact `PublicationAttempt`")
    publication = ledger.index(
        "writers emit\nonly their manifested bytes through the "
        "generation-fenced "
        "gateway", attempt)
    root_commit = ledger.index("one strong canonical-root/frontier CAS",
                               publication)
    commit_proof = ledger.index("post-commit signer re-read", root_commit)
    local_cert = ledger.index("local certifier", commit_proof)
    assert attempt < publication < root_commit < commit_proof < local_cert

    assert "RevocationActionBundle" in ledger
    assert re.search(r"detached author\s+signature", ledger)
    assert "deduplicates it" in ledger
    assert "partially\n  redundant `ExactSids(A, B)`" in ledger
    assert "terminal reserve" in contracts
    assert "detached-signature exhaustion" in shadow
    assert "observer of a committed but uncertified root fails closed" in cutover
    assert "successful B-only retry" in integration


def test_recovery_ledger_authenticates_slots_and_service_capacity():
    """A fid-only Worker read and a removal both have complete bounded proofs."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    shadow = "\n".join(strings(issues[f"{RECOVERY_EPIC}.5"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    performance = "\n".join(strings(issues[f"{RECOVERY_EPIC}.9"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    assert "SuppTree[SuppSlot(sid)] = CLEAR" in ledger
    assert "SuppTree[SuppSlot(sid)] = " \
        "ACTIVE(witness_removal_fid, witness_action_slot)" in ledger
    assert "FactTree[ActionSlot(owner(a))] =\n    " \
        "FILLED(action_record_oid)" in ledger
    assert "len(ActionRecord[action_record_oid]) <= " \
        "MAX_ACTION_RECORD_BYTES" in ledger
    assert "D    = { sid : SuppTree[SuppSlot(sid)] is authenticated `ACTIVE` }" \
        in ledger
    assert "A missing slot is never interpreted as clear" in ledger
    assert "A separate authoritative tree keyed only by removal fid" in ledger
    assert "`DIRECT_TARGETS` matrix" in ledger
    assert "target_fact_key, target_fact_record_oid, selector_token, " \
        "resolved_sid" in ledger
    assert "target_fact_key, target_fact_record_oid,\n    " \
        "principal_kind, resolved_public_key" in ledger
    assert "PrincipalProviderRegistry[(workspace, typed_principal_scope)]" \
        in ledger
    assert "CapacityEnvelope(" in ledger
    assert "fact_record_objects, fact_record_bytes" in ledger
    assert "raw_fact_chunk_objects, raw_fact_chunk_bytes" in ledger
    assert "authority_proof_record_objects, " \
        "authority_proof_record_bytes" in ledger
    assert "authority_proof_commit_rows, authority_proof_commit_bytes" \
        in ledger
    assert "authority_proof_commit_proof_objects" in ledger
    assert "legacy_authority_proof_objects, " \
        "legacy_authority_proof_bytes" in ledger
    assert "legacy_universe_map_objects, legacy_universe_map_bytes" in ledger
    assert "legacy_entry_map_objects, legacy_entry_map_bytes" in ledger
    assert "legacy_iam_attestation_objects, " \
        "legacy_iam_attestation_bytes" in ledger
    assert "legacy_migration_seal_objects, " \
        "legacy_migration_seal_bytes" in ledger
    assert "admit_cells, admit_cell_bytes" in ledger
    assert "principal_provider_registry_rows, " \
        "principal_provider_registry_bytes" in ledger
    assert "MAX_PRINCIPAL_PROVIDER_REGISTRY_VALUE_BYTES = 32 * 1024" \
        in ledger
    assert "MAX_AUTHORITY_PROOF_RECORD_BYTES = 64 * 1024" in ledger
    assert "MAX_LEGACY_AUTHORITY_PROOF_PAGE_FACTS = 64" in ledger
    assert "MAX_LEGACY_AUTHORITY_PROOF_PAGE_EDGES = 128" in ledger
    assert "MAX_LEGACY_AUTHORITY_PROOF_PAGE_BYTES = 64 * 1024" in ledger
    assert "admission_log_rows, admission_log_bytes" in ledger
    assert "target_registry_rows, target_registry_bytes" in ledger
    assert "authority_candidate_registry_rows, " \
        "authority_candidate_registry_bytes" in ledger
    assert "publication_attempt_manifest_rows" in ledger
    assert "publication_attempt_write_leases" in ledger
    assert "raw_fact_commit_rows, raw_fact_commit_bytes" in ledger
    assert "raw_fact_manifest_objects, raw_fact_manifest_bytes" in ledger
    assert "raw_fact_commit_pin_rows, raw_fact_commit_pin_bytes" in ledger
    assert "raw_fact_commit_pin_proof_objects, " \
        "raw_fact_commit_pin_proof_bytes" in ledger
    assert "MAX_CONTENT_COMMIT_PIN_BYTES = 8 * 1024" in ledger
    assert "MAX_CONTENT_COMMIT_PIN_PROOF_BYTES = 8 * 1024" in ledger
    assert "certificate_objects, certificate_bytes, " \
        "certificate_write_leases" in ledger
    assert "served_cell_rows, served_cell_bytes" in ledger
    assert "inclusion_witness_rows, inclusion_witness_bytes" in ledger
    assert "AuthorityImpactRegistry" in ledger
    assert "AuthorityCandidateRegistry" in ledger
    assert "conditional `admit/` cell" in ledger
    assert "changed_tree_paths(a) <= p + m + c" in ledger
    assert "pages_per_value_update <= MAX_TREE_DEPTH" in ledger
    assert "uniquely represented B-treap" in shadow
    assert "reserved suppression/action slots" in shadow
    assert "service-envelope" in cutover
    assert "PublicationAttempt" in cutover
    assert "AuthorityImpactRegistry" in contracts
    assert "AuthorityCandidateRegistry" in contracts
    assert "candidate_id binds NeedKey" in contracts
    assert "arrival-order independent" in contracts
    assert "transitive authority" in shadow
    assert "generation seal" in cutover
    assert "maximum-`ExactSids`" in performance
    assert "timestamp sorts before" in ledger
    assert "opposite arrival orders" in integration


def test_device_revocation_is_key_wide_and_future_safe():
    """Stable validation permits duplicate providers, so SELF alone is unsafe."""
    from facts.auth.device import device, validate
    from facts.auth.device_invite import device_invite

    public_key = "same-device-key"
    first = device(public_key, "phone", 1)
    second = device(public_key, "laptop", 2)
    dual_scope = device_invite("signer", "user", public_key, "tablet", 3)
    assert first.fid != second.fid
    assert validate(first, None)
    assert validate(second, None)
    assert ("member", public_key, "") in dual_scope.offers()
    assert ("device_key", public_key, "") in dual_scope.offers()

    ledger = (ROOT / "docs" / "TODO.md").read_text()
    normalized = " ".join(ledger.split())
    assert "DevicePrincipal(public_key)" in ledger
    assert "DevicePrincipal(PrincipalBinding(...))" in ledger
    assert "different labels or timestamps produce several valid device facts" \
        in normalized
    assert "A later provider may implement several typed scopes at once" \
        in ledger
    assert "initial effective set is **every** committed `MemberPrincipal` " \
        "and\n`DevicePrincipal` tombstone" in ledger
    assert "never the first matching registry\nrow" in ledger
    assert "`effect_targets` reads the `provider_fid`\nfields from this " \
        "bounded registry rather than scanning FactTree" in ledger
    assert "MAX_DEVICE_PROVIDERS_PER_PRINCIPAL = 64" in ledger
    assert "MAX_PRINCIPAL_SCOPES_PER_FACT = 2" in ledger


def test_overlapping_actions_keep_canonical_witness_and_both_owners():
    """A principal tombstone must not erase an earlier exact action's evidence."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))
    assert "effective_actions(root, sid)" in ledger
    assert "witness(root, sid) =" in ledger
    assert "both ActionSlots remain filled" in ledger
    assert "dual-scope fixture commits\n  member and device tombstones" in ledger
    assert re.search(
        r"canonical-witness `ACTIVE` SuppSlot and the\s+receipt's own filled "
        r"owner ActionSlot",
        ledger,
    )
    assert "overlapping actions retain both ActionSlots" in contracts
    assert "both overlapping ActionSlots plus canonical witness" in integration
    assert "dual-scope later provider" in contracts
    assert "first-typed-tombstone" in integration


def test_revocation_capacity_charges_out_of_line_fact_evidence():
    """Escrow includes proposal/support/receipt objects, not only tree rows."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    normalized = " ".join(ledger.split())
    assert "MAX_REVOCATION_RECORD_RAW_BYTES = 32 * 1024" in ledger
    assert "MAX_ADMISSION_PROOF_BYTES = 56 * 1024" in ledger
    assert "MAX_PENDING_BUNDLE_FRAMING_BYTES = 8 * 1024" in ledger
    assert "MAX_PENDING_BUNDLE_BYTES = 64 * 1024" in ledger
    assert "MAX_ADMISSION_PROOF_REFS = 7" in ledger
    assert "MAX_ACTION_EVIDENCE_REFS = 8" in ledger
    assert "MAX_REVOCATION_BASE_RECORDS = 13" in ledger
    assert "MAX_REVOCATION_BASE_TREE_PATHS = 1" in ledger
    assert "MAX_ADMIT_CELL_BYTES = 32 * 1024" in ledger
    assert "every out-of-line certified FactRecord" in ledger
    assert "raw_fact_chunk_*` charges every immutable" in ledger
    assert "sum(canonical_raw_bytes(proof_refs)) <= " \
        "MAX_ADMISSION_PROOF_BYTES" in ledger
    assert "Revocation liability charges\nthe proof aggregate plus the " \
        "maximum receipt" in ledger
    assert (
        "one full `MAX_FACT_RECORD_BYTES` for each of the at-most-eight "
        "evidence FactRecords"
    ) in normalized
    assert (
        "Raw evidence is charged once at "
        "`MAX_ADMISSION_PROOF_BYTES + MAX_REVOCATION_RECORD_RAW_BYTES`"
    ) in normalized
    assert "never eight independently maximal raw chunks" in normalized
    assert "per-record-max-raw-proof-liability" in ledger
    assert 56 * 1024 + 8 * 1024 == 64 * 1024
    assert 56 * 1024 + 32 * 1024 < 8 * 32 * 1024
    assert "at most\n`MAX_REVOCATION_BASE_RECORDS = 13` logical records" \
        in ledger
    assert "Only the\npreallocated owner `ActionSlot` is a base tree path" \
        in ledger
    assert "one full `MAX_ADMIT_CELL_BYTES` reservation" in normalized


def test_worker_bound_applies_to_records_not_existing_raw_facts():
    """Large immutable content is chunked; only request metadata is hard-capped."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "MAX_FACT_RECORD_BYTES = 32 * 1024" in ledger
    assert "MAX_FACT_CHUNK_BYTES  = 32 * 1024" in ledger
    assert "MAX_FACT_BYTES        = 32 * 1024" not in ledger
    assert re.search(
        r"Existing unbounded message\s+text is therefore\s+representable",
        ledger,
    )


def test_large_raw_facts_commit_outside_the_fixed_metadata_attempt():
    """Raw content stays ordered, convergent, pinned, and out of metadata."""
    from core.fact import canon, from_json
    from facts.content.message import message

    ledger = (ROOT / "docs" / "TODO.md").read_text()
    chunk_count = 64 * 8 + 1
    manifest_page_count = (chunk_count + 64 - 1) // 64
    content_batch_count = (chunk_count + 64 - 1) // 64
    metadata_commit_refs = 1
    candidates = [f"raw-chunk-{index}".encode() for index in range(32)]
    first, second = next(
        (left, right)
        for left in candidates
        for right in candidates
        if hashlib.sha256(left).digest() > hashlib.sha256(right).digest()
    )
    ordered_chunks = (first, second, first)
    chunk_oids = tuple(
        hashlib.sha256(chunk).hexdigest() for chunk in ordered_chunks
    )
    entries = tuple(
        {
            "ordinal": ordinal,
            "byte_start": sum(map(len, ordered_chunks[:ordinal])),
            "byte_len": len(chunk),
            "chunk_oid": chunk_oids[ordinal],
        }
        for ordinal, chunk in enumerate(ordered_chunks)
    )
    raw = b"".join(ordered_chunks)
    rebuilt = b"".join(
        ordered_chunks[entry["ordinal"]]
        for entry in sorted(entries, key=lambda entry: entry["ordinal"])
    )
    wrong_oid_order = b"".join(
        chunk
        for _, chunk in sorted(
            zip(chunk_oids, ordered_chunks), key=lambda item: item[0]
        )
    )
    ordering_manifest_oid = hashlib.sha256(json.dumps(
        entries, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    fact = message("p" * 64, "general", "content identity", 42)
    canonical_fact_bytes = canon(fact.to_json())
    raw_root_oid = hashlib.sha256(canonical_fact_bytes).hexdigest()
    decoded = from_json(json.loads(canonical_fact_bytes))
    fact_entries = (
        {
            "ordinal": 0,
            "byte_start": 0,
            "byte_len": len(canonical_fact_bytes),
            "chunk_oid": raw_root_oid,
        },
    )
    manifest_oid = hashlib.sha256(json.dumps(
        fact_entries, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    canonical_commit = {
        "workspace": "workspace",
        "fid": fact.fid,
        "raw_root_oid": raw_root_oid,
        "raw_manifest_root_oid": manifest_oid,
        "raw_bytes": len(canonical_fact_bytes),
        "raw_objects": 2,
    }

    def commit_id(commit):
        return hashlib.sha256(json.dumps(
            commit, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()

    retry_ids = {
        generation: commit_id(canonical_commit)
        for generation in (7, 8)
    }
    old_generation_bound_ids = {
        generation: commit_id({
            **canonical_commit,
            "content_generation": generation,
        })
        for generation in (7, 8)
    }
    pin = {
        "state": "PENDING",
        "pin_epoch": 1,
        "attempt_id": "attempt-7",
        "attempt_generation": 7,
    }
    can_collect = lambda value: value["state"] == "ABORTED"

    def can_accept_write(value, epoch, generation):
        return value == {
            "state": "PENDING",
            "pin_epoch": epoch,
            "attempt_id": f"attempt-{generation}",
            "attempt_generation": generation,
        }

    assert manifest_page_count == 9 > 8
    assert content_batch_count == 9
    assert metadata_commit_refs <= 8
    assert rebuilt == raw
    assert wrong_oid_order != raw
    assert entries[0]["chunk_oid"] == entries[2]["chunk_oid"]
    assert tuple(entry["ordinal"] for entry in entries) == (0, 1, 2)
    assert ordering_manifest_oid != manifest_oid
    assert decoded == fact
    assert decoded.fid == canonical_commit["fid"]
    assert raw_root_oid != fact.fid
    assert len(set(retry_ids.values())) == 1
    assert len(set(old_generation_bound_ids.values())) == 2
    assert not can_collect(pin)
    aborted = {
        "state": "ABORTED",
        "pin_epoch": 1,
        "fenced_generation": 7,
    }
    assert can_collect(aborted)
    retry_pin = {
        "state": "PENDING",
        "pin_epoch": aborted["pin_epoch"] + 1,
        "attempt_id": "attempt-8",
        "attempt_generation": 8,
    }
    assert not can_collect(retry_pin)
    assert can_accept_write(retry_pin, 2, 8)
    assert not can_accept_write(retry_pin, 1, 7)
    rooted = {
        "state": "ROOTED",
        "committed_root_oid": "r" * 64,
        "frontier_serial": 9,
    }
    assert not can_collect(rooted)
    cutover_states = ("STAGING", "SEALED", "ROOTED")
    assert all(not can_collect({"state": state}) for state in cutover_states)
    assert can_collect({
        "state": "ABORTED",
        "fenced_service_generation": 11,
    })
    assert "RawFactContentCommit(" in ledger
    assert "RawFactContentCommitProof =" in ledger
    assert "RawFactChunkRef(ordinal, byte_start, byte_len, chunk_oid)" \
        in ledger
    assert "Chunk oids are integrity fields, never sort keys" in ledger
    assert "Hashing the complete raw JSON directly as the fid is invalid" \
        in ledger
    assert "It is not a field of `RawFactContentCommit`" in ledger
    assert "ContentCommitPin[PENDING]" in ledger
    assert "`pin_epoch` is a monotonic per-pin counter" in ledger
    assert "`CutoverContentPinGeneration" in ledger
    assert "`ContentCommitPinProof`" in ledger
    assert "GC may collect only an `ABORTED` pin" in ledger
    assert "MAX_RAW_FACT_MANIFEST_PAGE_ENTRIES = 64" in ledger
    assert "MAX_RAW_FACT_MANIFEST_PAGE_BYTES = 64 * 1024" in ledger
    assert "MAX_RAW_FACT_CONTENT_BATCH_OBJECTS = 64" in ledger
    assert "fixed metadata\n`PublicationAttempt`" in ledger
    assert "manifests that bounded record and\nclaim/commit proof reference, " \
        "not the raw chunks or manifest pages" in ledger
    assert "inline-raw-fact-chunks-overflow-publication-attempt" in ledger
    assert "sort-raw-manifest-by-chunk-oid" in ledger
    assert "content-generation-in-canonical-commit" in ledger
    assert "hash-raw-bytes-as-fid" in ledger
    assert "aborted-content-pin-blocks-retry" in ledger
    assert "collect-sealed-content-before-metadata-cas" in ledger
    assert "collect-sealed-cutover-generation" in ledger


def test_recovery_ledger_keeps_legacy_authority_and_revocation_serviceable():
    """Migration and capacity limits cannot strand a valid legacy principal."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "MAX_MEMBERSHIP_PROVIDERS_PER_PRINCIPAL = 64" in ledger
    assert "LegacyAuthorityCheckpoint" in ledger
    assert "A sealed valid 519-hop membership chain migrates" in ledger
    assert "emits zero SuppTree effect\n   updates" in ledger
    assert "valid removal of every\n  already-admitted target succeeds" in ledger
    assert "activates the writable S4 fallback generation" in ledger
    assert "no recoverable initial target is a hard" not in ledger


def test_worker_lookup_budget_fits_cloudflare_subrequest_limit():
    """The cold-cache proof must not rely on path sharing or batching."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()

    def constant(name):
        match = re.search(rf"^{name}\s*=\s*(\d+)", ledger, re.MULTILINE)
        assert match, name
        return int(match.group(1))

    reads = (
        constant("MAX_POINT_LOOKUPS") * constant("MAX_TREE_DEPTH")
        + constant("MAX_WORKER_FACTS")
        + 2  # current root and its local certificate
        + constant("MAX_SERVED_SUBREQUESTS")
    )
    assert reads == 867
    assert constant("MAX_SUPPRESSION_LOOKUPS") == \
        constant("MAX_WORKER_SELECTORS")
    assert constant("MAX_EXACT_SIDS_PER_REMOVAL") <= \
        constant("MAX_EFFECT_TARGETS_PER_REMOVAL")
    assert constant("MAX_MEMBERSHIP_PROVIDERS_PER_PRINCIPAL") == \
        constant("MAX_EFFECT_TARGETS_PER_REMOVAL")
    assert constant("MAX_DEVICE_PROVIDERS_PER_PRINCIPAL") == \
        constant("MAX_EFFECT_TARGETS_PER_REMOVAL")
    assert constant("MAX_PRINCIPAL_SCOPES_PER_FACT") == 2
    assert constant("MAX_ACTION_IMPACT_SCOPES") == \
        constant("MAX_EFFECT_TARGETS_PER_REMOVAL") + 1 == 65
    changed_paths = (
        constant("MAX_REVOCATION_BASE_TREE_PATHS")
        + constant("MAX_EFFECT_TARGETS_PER_REMOVAL")
        + constant("MAX_AUTHORITY_CONSEQUENCES_PER_ACTION")
    )
    assert constant("MAX_ADMISSION_PROOF_REFS") == 7
    assert constant("MAX_ACTION_EVIDENCE_REFS") == 8
    assert constant("MAX_REVOCATION_BASE_RECORDS") == 13
    assert constant("MAX_REVOCATION_BASE_TREE_PATHS") == 1
    assert constant("MAX_AUTHORITY_CANDIDATES_PER_NEED") == 64
    assert constant("MAX_AUTHORITY_CANDIDATE_REFS_PER_ACTION") == (
        constant("MAX_AUTHORITY_CONSEQUENCES_PER_ACTION")
        * constant("MAX_AUTHORITY_CANDIDATES_PER_NEED")
    ) == 4_096
    assert changed_paths == constant("MAX_CHANGED_TREE_PATHS") == 129
    pages_per_insert = 2 * constant("MAX_TREE_DEPTH") + 1
    assert pages_per_insert == constant("MAX_TREE_PAGES_PER_INSERT") == 17
    pages_per_update = constant("MAX_TREE_DEPTH")
    assert pages_per_update == \
        constant("MAX_TREE_PAGES_PER_VALUE_UPDATE") == 8
    assert changed_paths * pages_per_update == \
        constant("MAX_CHANGED_PAGE_OBJECTS") == 1_032
    ordinary_insert_kinds = (
        ("FactSlot", 1),
        ("SELF SuppSlot", 1),
        ("direct SELF ActionSlot", 1),
        ("typed-principal ActionSlots", 2),
        ("AuthorityTree NeedKeys", 8),
    )
    ordinary_inserts = sum(count for _, count in ordinary_insert_kinds)
    assert ordinary_inserts == constant("MAX_ORDINARY_TREE_INSERTS") == 13
    assert ordinary_inserts * pages_per_insert == \
        constant("MAX_ORDINARY_CHANGED_PAGE_OBJECTS") == 221
    assert ordinary_inserts + 1 > constant("MAX_ORDINARY_TREE_INSERTS")
    assert reads < constant("MAX_R2_SUBREQUESTS") < 1_000


def test_publication_attempts_fence_delayed_writers_before_release():
    """A reclaimed generation cannot recreate uncharged canonical objects."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "`generation` comes from a monotonic workspace counter" in ledger
    assert "`OPEN`, `SEALING`, `ABORTING`, or `COMMITTED_COPYING`" in ledger
    assert "Publishers receive no raw **metadata-write** object-store " \
        "credential" in ledger
    assert "AttemptWriteLease(generation, manifest_index, state)" in ledger
    assert "generation-fences and drains its object, certificate and witness\n" \
        "writers before clearing any reservation" in ledger
    assert "charges every canonical object before authority-exclusive" in ledger


def test_certificate_capacity_is_reserved_before_cas_and_reclaimed():
    """A committed root cannot be stranded without its serving certificate."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    reservation = ledger.index("claims one bounded next-root certificate")
    root_commit = ledger.index(
        "performing the one strong canonical-root/frontier CAS",
        reservation,
    )
    assert reservation < root_commit
    serving_reservation = ledger.index(
        "`PublisherCapacityCell` aggregate still equals the capacity reserved",
        reservation,
    )
    assert reservation < serving_reservation < root_commit
    assert "never loops over publishers or writes their rows" in ledger
    assert "Every other publisher that\nobserves the new root fails closed, " \
        "independently certifies it off-request" in ledger
    assert "certificate_objects, certificate_bytes, " \
        "certificate_write_leases" in ledger
    assert "service never commits a root whose publishing deployment " \
        in " ".join(ledger.split())
    assert "cannot materialize `cert/<root_oid>`" in ledger
    assert "`cert/<root_oid>` object remains charged while that root is " \
        "current" in ledger
    assert "deletes the sidecar and reclaims its\nobject/byte slot" in ledger
    assert "Another publisher\nwhose precharged local reserve is later " \
        "unavailable fails closed" in ledger
    assert "missing next-certificate\n  reservation prevents the canonical " \
        "CAS" in ledger


def test_worker_reads_hold_a_root_and_certificate_lease():
    """Concurrent served-cell advances cannot mix or collect an active read."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    normalized = " ".join(ledger.split())

    authorize = ledger.index(
        "`WorkerReadLease(publisher_id, lease_slot, lease_generation, root_oid,"
    )
    gateway = ledger.index(
        "Every FactTree, SuppTree, AuthorityTree and immutable-page fetch",
        authorize,
    )
    concurrent = ledger.index(
        "Request A may therefore finish reads from R while",
        gateway,
    )
    assert authorize < gateway < concurrent
    assert "MAX_WORKER_READ_LEASES_PER_PUBLISHER = 64" in ledger
    assert "MAX_WORKER_READ_LEASE_BYTES = 4 * 1024" in ledger
    assert "MAX_WORKER_READ_LEASE_MS = 60 * 1000" in ledger
    assert "worker_read_lease_rows, worker_read_lease_bytes" in ledger
    assert "precreates `MAX_WORKER_READ_LEASES_PER_PUBLISHER` fixed " \
        "overwrite-only lease\nrows" in ledger
    assert (
        "The response is the signed freshness/read token naming that exact "
        "lease generation, root oid, certificate oid and expiry"
    ) in normalized
    assert (
        "Every tree, FactRecord and immutable-page read in steps 2–5 must "
        "present that token"
    ) in normalized
    assert (
        "Bind a grant to the certified root oid/etag and the same "
        "`WorkerReadLease` generation"
    ) in normalized
    assert "grant expiry cannot\n   exceed the lease expiry" in ledger
    assert "R's pages and certificate remain charged until A\n  releases " \
        "or expires" in ledger
    assert "served-cell-only-read-lease" in ledger
    assert "unbound-read-token" in ledger


def test_mandatory_service_rows_and_migration_seal_have_byte_capacity():
    """Mandatory durable service values cannot hide behind object counts."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    normalized = " ".join(ledger.split())
    assert "admit_cells, admit_cell_bytes" in ledger
    assert "MAX_ADMIT_CELL_BYTES = 32 * 1024" in ledger
    assert "retains the complete canonical signed receipt" in ledger
    assert "charges its exact encoding and\nadmission also rejects any cell " \
        "above `MAX_ADMIT_CELL_BYTES`" in ledger
    assert "legacy_migration_seal_objects, " \
        "legacy_migration_seal_bytes" in ledger
    assert "MAX_LEGACY_MIGRATION_SEAL_BYTES = 4 * 1024" in ledger
    assert "the seal allocation includes one object of\nat most " \
        "`MAX_LEGACY_MIGRATION_SEAL_BYTES`" in ledger
    assert "unbounded publisher count lives\nas individually capped rows in " \
        "the paged universe map" in ledger
    assert "legacy_iam_attestation_objects, " \
        "legacy_iam_attestation_bytes" in ledger
    assert "MAX_LEGACY_IAM_ATTESTATION_BYTES = 32 * 1024" in ledger
    assert "The IAM allocation includes one content-addressed object of at " \
        "most\n`MAX_LEGACY_IAM_ATTESTATION_BYTES`" in ledger
    assert "served_cell_rows, served_cell_bytes" in ledger
    assert "inclusion_witness_rows, inclusion_witness_bytes" in ledger
    assert "MAX_SERVED_CELL_BYTES = 4 * 1024" in ledger
    assert "MAX_INCLUSION_WITNESS_BYTES = 4 * 1024" in ledger
    assert "MAX_PUBLISHER_CAPACITY_CELL_BYTES = 4 * 1024" in ledger
    assert "`served/<workspace>/<publisher_id>` row" in ledger
    assert "`witness/<workspace>/<publisher_id>` row" in ledger
    assert "publisher_capacity_cells, publisher_capacity_bytes" in ledger
    assert "`PublisherCapacityCell(workspace)`" in ledger
    assert "mandatory serving capacity, not best-effort caches" in normalized
    assert "worker_read_lease_rows, worker_read_lease_bytes" in ledger
    assert "MAX_WORKER_READ_LEASES_PER_PUBLISHER = 64" in ledger
    assert "MAX_WORKER_READ_LEASE_BYTES = 4 * 1024" in ledger
    assert "target_registry_rows, target_registry_bytes" in ledger
    assert "MAX_TARGET_REGISTRY_ROW_BYTES = 512" in ledger
    assert "Row availability without byte availability is\ntherefore not " \
        "sufficient to sign or commit the action" in ledger
    assert "canonical_root_cells, canonical_root_bytes" in ledger
    assert "frontier_cells, frontier_bytes" in ledger
    assert "active_service_generation_cells, " \
        "active_service_generation_bytes" in ledger
    assert "MAX_FRONTIER_CELL_BYTES = 8 * 1024" in ledger
    assert "MAX_ACTIVE_SERVICE_GENERATION_CELL_BYTES = 8 * 1024" in ledger
    assert "cutover_payload_manifest_objects, " \
        "cutover_payload_manifest_bytes" in ledger
    assert "cutover_commit_anchor_cells, cutover_commit_anchor_bytes" in ledger
    assert "MAX_CUTOVER_COMMIT_ANCHOR_BYTES = 8 * 1024" in ledger


def test_revocation_escrow_bounds_transitive_authority_fanout():
    """Neither reverse fanout nor losing-provider width may require a scan."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert re.search(r"monotonic conservative set\s+of `NeedKey`s", ledger)
    assert "losing/fallback providers" in ledger
    assert "complete proof closure" in ledger
    assert "transitive reverse\nfan-out" in ledger
    assert re.search(
        r"sixty-fifth consequence or\s+sixty-fifth candidate for one NeedKey "
        r"rejects the new provider",
        ledger,
    )
    assert re.search(r"direct children alone are\s+not a valid count", ledger)
    assert "MAX_AUTHORITY_IMPACT_SCOPES_PER_PUBLICATION = 64" in ledger
    assert "AuthorityCandidateRegistry[(workspace, NeedKey)]" in ledger
    assert "candidate_id, provider_fid, provider_fact_record_oid,\n" \
        "    authority_proof_record_oid, authority_proof_commit_id" in ledger
    assert "AuthorityProofRecord(" in ledger
    assert "distinct valid proof closures for the same provider are distinct " \
        "candidates" in " ".join(ledger.split())
    assert "mask_witness(root, candidate)" in ledger
    assert "canonical rather than arrival-order-dependent" in ledger
    assert "MAX_AUTHORITY_CANDIDATES_PER_NEED = 64" in ledger
    assert "MAX_AUTHORITY_CANDIDATE_REFS_PER_ACTION = 4096" in ledger
    assert "never scans\nFactTree or an unbounded provider population" in ledger
    assert "authority_candidate_registry_rows, " \
        "authority_candidate_registry_bytes" in ledger
    assert "submitted provider fid and closed-proof digest" in ledger


def test_registry_values_fit_atomic_publication_by_pointer():
    """Maximal revocation stages full values but atomically flips only pointers."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    need_intro_directories = 8
    provider_directories = 8
    need_directories = need_intro_directories + provider_directories
    base_candidate_values = 8
    provider_full_candidate_values = 64
    introduced_full_candidate_values = 8
    full_candidate_values = (
        provider_full_candidate_values + introduced_full_candidate_values
    )
    impact_values = 64
    principal_values = 2
    registry_objects = (
        need_directories
        + base_candidate_values
        + full_candidate_values
        + impact_values
        + principal_values
    )
    registry_bytes = (
        (base_candidate_values + full_candidate_values) * 512 * 1024
        + (need_directories + impact_values + principal_values) * 32 * 1024
    )
    inline_candidate_bytes = full_candidate_values * 512 * 1024
    pointer_commit_bytes = 168 * 1024 + registry_objects * 256

    assert registry_objects == 162
    assert registry_bytes == 44_630_016
    assert inline_candidate_bytes > 512 * 1024
    assert 31 + registry_objects == 193
    assert pointer_commit_bytes == 213_504 < 512 * 1024
    assert 64 * (320 + 1) + 2 == 20_546 < 32 * 1024
    assert "RegistryValueObject(kind, workspace, logical_key, " \
        "canonical_value)" in ledger
    assert "RegistryValuePointer(registry_value_oid, canonical_value_bytes)" \
        in ledger
    assert "MAX_AUTHORITY_IMPACT_REGISTRY_VALUE_BYTES = 32 * 1024" in ledger
    assert "MAX_BASE_OFFER_NEED_KEY_VALUES_PER_PUBLICATION = 16" in ledger
    assert "MAX_PROVIDER_AUTHORITY_CANDIDATE_VALUES_PER_PUBLICATION = 64" \
        in ledger
    assert "MAX_AUTHORITY_CANDIDATE_VALUES_PER_PUBLICATION = 72" in ledger
    assert "MAX_PUBLICATION_REGISTRY_VALUE_OBJECTS = 162" in ledger
    assert "MAX_PUBLICATION_REGISTRY_VALUE_BYTES = 44_630_016" in ledger
    assert "MAX_PUBLICATION_FIXED_SERVICE_ROWS = 31" in ledger
    assert "MAX_PUBLICATION_FIXED_SERVICE_BYTES = 168 * 1024" in ledger
    assert "MAX_PUBLICATION_SERVICE_TRANSACTION_ROWS = 193" in ledger
    assert "MAX_PUBLICATION_SERVICE_TRANSACTION_BYTES = 512 * 1024" in ledger
    assert "MAX_PUBLICATION_ATTEMPT_MANIFEST_ROWS = 8" in ledger
    assert "MAX_PUBLICATION_ATTEMPT_MANIFEST_BYTES = 256 * 1024" in ledger
    assert "principal_provider_registry_value_objects" in ledger
    assert "base_offer_need_key_registry_value_objects" in ledger
    assert "authority_base_candidate_registry_value_objects" in ledger
    assert "authority_candidate_registry_value_objects" in ledger
    assert "authority_impact_registry_value_objects" in ledger
    assert "`AtomicCommitBudget(root)`" not in ledger
    assert "AtomicCommitBudget(action_bundle)" in ledger
    assert "publishing a new authority candidate or reverse relationship " \
        "recomputes every\naffected target/principal witness" in ledger
    assert "one content-pin transition" in ledger
    assert "inline-registry-values-overflow-atomic-commit" in ledger
    assert "unbounded-authority-impact-value" in ledger


def test_authority_candidate_masks_follow_declared_liveness_guards():
    """Incidental proof support cannot override family revocation policy."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    shadow = "\n".join(strings(issues[f"{RECOVERY_EPIC}.5"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))
    proof_support_sids = {"fact:grantee", "fact:grantor"}
    provider_sids = {"fact:delegation"}
    declared_liveness_sids = {"fact:grantee"}
    worker_sids = provider_sids | declared_liveness_sids
    admitted_candidate = {
        "admission": "ADMITTED_PROOF",
        "mask": "CLEAR",
        "proof": ("grantee", "grantor-v1"),
    }
    after_incidental_winner_change = {
        **admitted_candidate,
        "current_grantor_winner": "grantor-v2",
    }

    assert worker_sids < proof_support_sids | provider_sids
    assert "fact:grantor" not in worker_sids
    assert after_incidental_winner_change["admission"] == "ADMITTED_PROOF"
    assert after_incidental_winner_change["mask"] == "CLEAR"
    assert after_incidental_winner_change["proof"] == \
        admitted_candidate["proof"]
    assert "`AUTHORITY_LIVENESS_GUARDS`: the exact named proof edges" in ledger
    assert "Merely appearing somewhere in a\ncandidate's proof closure never " \
        "makes a fact a continuing liveness guard" in ledger
    assert "`sorted_action_scopes` is the exact union of resolved\n" \
        "`AUTHORITY_LIVENESS_GUARDS`" not in ledger
    assert "`sorted_action_scopes` is separately the exact deduplicated " \
        "expansion" in ledger
    assert "`FollowAuthority(path)` recursively imports" in ledger
    assert "incidental support fact or one-time `AUTHORIZATION_GUARD` " \
        "contributes no scope" in " ".join(ledger.split())
    assert "Complete proof closure remains authentication evidence, not an " \
        "ambient\nrevocation policy" in ledger
    assert "grantee-only and grantor-only" in ledger
    assert "AUTHORITY_LIVENESS_GUARDS" in contracts
    assert "declared liveness guards" in shadow
    assert "family-declared authority liveness" in cutover
    assert "closure-wide-candidate-masking" in integration
    assert "guard_actions(root, Sid(sid))" in ledger
    assert "effective_actions(root, sid)" in ledger
    assert "impact_scopes(root, MemberPrincipal(binding))" in ledger
    assert "principal-scope-does-not-mask-sid-guard" in integration
    assert "sorted_provider_sids, sorted_action_scopes" in ledger
    assert "candidate.sorted_provider_sids" in ledger
    assert "A candidate can never remain usable after its own provider " \
        "record is\nsuppressed" in ledger
    assert "migration-only sid masks candidates produced by\nits exact " \
        "`LegacyMask` victim" in ledger
    assert "legacy-mask-authority-provider-stays-live" in ledger
    assert "it does **not** make every support\n   fact's suppression selectors " \
        "part of the request" in ledger
    assert "request fact's own family-declared selectors plus, for each " \
        "selected\n   authority candidate, its mandatory provider selectors" \
        in ledger
    assert "worker-suppresses-all-proof-evidence" in ledger
    assert "does not re-resolve against later AuthorityTree winners" in ledger
    assert "reresolve-admitted-proof-against-current-winner" in ledger
    assert "AuthorityProofCommitProof" in ledger


def test_admin_liveness_and_content_deletion_policy_are_settled():
    """S2 must not leave either application policy to an implementation guess."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    delete_handler = (ROOT / "facts" / "content" / "delete.py").read_text()
    normalized = " ".join(ledger.split())
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = {
        stage: " ".join(strings(issues[f"{RECOVERY_EPIC}.{stage}"]))
        for stage in (2, 4, 5, 6, 7, 10)
    }
    epic_contract = " ".join(strings(issues[RECOVERY_EPIC]))

    assert "**OPEN application policy" not in ledger
    assert "delegated-admin provider has **grantee-only continuing liveness**" \
        in ledger
    assert "one-time\n  `AUTHORIZATION_GUARD`, not an " \
        "`AUTHORITY_LIVENESS_GUARD`" in ledger
    assert "no `FollowAuthority(grantor-admin)`" in ledger
    assert "`DeleteOffer(\"content.delete\", SELF, " \
        "OwnerBinding(...))`" in ledger
    assert "exact provider fact key/fid/FactRecord oid" in normalized
    assert "AuthorityProofRecord, CommittedAuthorityProof row and " \
        "AuthorityProofCommitProof" in normalized
    assert "two explicit proposal modes, `OWNER` and `ADMIN`" in ledger
    assert "ordinary conjunctive needs tuple" in ledger
    assert "receipt is the later post-proposal commit gate, not a proposal " \
        "need" in normalized
    assert "The receipt is deliberately absent from both tuples" in ledger
    assert "has absolute precedence and makes the signing key act as itself" \
        in normalized
    assert "any admitted, shape-valid direct-member claimant" in normalized
    assert "including a masked one" in normalized
    assert "If all such providers are suppressed the action fails, and it " \
        "never falls through to a device claim" in normalized
    assert "`DEVICE` therefore means no direct-member claimant exists" \
        in normalized
    assert "A bare `device_invite` is also never ownership consent" in ledger
    assert "DeviceOwnerConsent(workspace, device_key, owner_principal," \
        in ledger
    assert "A bare `device_invite` cannot be the target of " \
        "`DevicePrincipal`" in ledger
    assert "key-signed self-bound `device` or `DeviceOwnerConsent` row" \
        in normalized
    assert "without the target-key signature" in normalized
    assert "self-owned `device` provider seeds that user's device set and is " \
        "not a `DEVICE` ownership candidate" in normalized
    assert "Actor class is serialization-relative, not globally monotonic" \
        in ledger
    assert "later direct rejoin may legitimately rerank a formerly " \
        "device-only signing key" in normalized
    assert "ActorBindingProof =" in ledger
    assert "ActorBasis =" not in ledger
    assert "canon(workspace, target_fact_key, target_fid," in ledger
    assert "No mutable root oid, frontier serial, retry generation or current " \
        "winner enters the signed statement" in normalized
    assert "without retaining the historical root" in normalized
    assert "MAX_ACTOR_BINDING_PROOF_BYTES = 4 * 1024" in ledger
    assert "advances and commit-proves the provider first" in normalized
    assert "LegacyActorAdmissionRecord =" in ledger
    assert "CommittedLegacyActorAdmission[" in ledger
    assert "LegacyActorAdmissionProofSlot[" in ledger
    assert "LegacyActorAdmissionCommitProof[" in ledger
    assert "legacy_actor_admission_record_oid =" in ledger
    assert "legacy_actor_admission_commit_id =" in ledger
    assert "does **not** rerun direct-member precedence over the frozen S4 " \
        "set" in normalized
    assert "cannot be synthesized from a later root" in normalized
    assert "facts already present when this recorder is deployed may lack " \
        "migration evidence" in normalized
    assert "never chooses an owner by replaying current direct-member " \
        "precedence" in normalized
    assert "evidence beyond both the native proof cap and signed paged " \
        "checkpoint/source ceilings" in normalized
    assert "S4_DEVICE_INVITE_ACCEPTANCE" in ledger
    assert "The contextual signature is acceptance for this one target only" \
        in normalized
    assert "ordinary detached target signature alone is insufficient" \
        in normalized
    assert "s4-device-invite-acceptance-v1" in ledger
    assert "workspace, target_fact_key, target_fid, device_key, " \
        "owner_principal" in normalized
    assert "grants no reusable post-S5 actor authority" in normalized
    assert "An invite or ordinary target signature alone, without that " \
        "contextual acceptance, is insufficient" \
        in normalized
    assert "ActionAuthorization =" in ledger
    assert "OWNER(ActionActorBinding)" in ledger
    assert "ADMIN(ActionActorBinding, AdminAuthorityRef)" in ledger
    assert "GRANDFATHER(LegacyEffectAuthorizationRef)" in ledger
    assert "LegacyEffectAuthorizationRef =" in ledger
    assert "cross-user content deletion accepted by the legacy any-member " \
        "handler stays\n   effective" in ledger
    assert "if evidence_kind = LIVE_GUARDS:\n" \
        "    ActionAuthorization.ActionActorBinding" in ledger
    assert "    ActionAuthorization is not GRANDFATHER" in ledger
    assert "no live request path accepts GRANDFATHER" in ledger
    assert "MAX_ACTION_AUTHORIZATION_BYTES = 6 * 1024" in ledger
    assert "MAX_PENDING_BUNDLE_FRAMING_BYTES = 8 * 1024" in ledger
    assert "it is not charged to or accepted from caller-controlled pending " \
        "framing" in normalized
    assert "proof_refs(r), ActionAuthorization" in ledger
    assert "evidence_kind, evidence_fids, ActionAuthorization," in ledger
    assert "ActionAuthorization derived by the admission service" in ledger
    assert "a signed pre-CAS orphan is inert" in normalized
    assert "may not use S4_DEVICE_INVITE_ACCEPTANCE to authorize a new action" \
        in normalized
    assert "ActionAuthorization's bounded actor/admin provider FactRecords" \
        in normalized
    delete_guard = ledger.index(
        'if b selects delete_kind in {"content.delete", "device.grant.delete"}:')
    target_owner_check = ledger.index(
        "OwnerBinding.ActorBindingStatement.ActorAdmissionEvidence",
        delete_guard,
    )
    action_scope = ledger.index(
        "# The following authorization checks are action-scoped",
        target_owner_check,
    )
    next_unconditional_section = ledger.index(
        "FactRecord[p.provider_fact_record_oid]",
        action_scope,
    )
    assert delete_guard < target_owner_check < action_scope < \
        next_unconditional_section
    assert ledger.index(
        "if evidence_kind in {LEGACY_SLOT, LEGACY_GLOBAL}:",
        action_scope,
    ) < next_unconditional_section
    assert "not nested under any\n# TargetBinding or direct-delete branch" \
        in ledger
    assert "an admin may delete every fact whose type declares it deletable" \
        in ledger
    assert "ordinary user may delete only that user's own deletable facts" \
        in ledger
    assert "`ADMIN` instead carries one explicit `admin_scope`, `KEY` or " \
        "`OWNER`" in normalized
    assert "A grant to a device key `D` therefore remains exactly `admin(D)` " \
        "and authorizes only `D`" in normalized
    assert "never promotes `D`'s siblings" in normalized
    assert "a grant to user key `U` authorizes `U` under `KEY` and each " \
        "consenting device owned by `U` under `OWNER`" in normalized
    assert "AdminSubject(KEY, ActorBinding)" in ledger
    assert "no admin(device_key) provider can satisfy admin(owner_principal)" \
        in ledger
    assert "A target type with no suppression selector or no matching " \
        "`DIRECT_TARGETS`/`DeleteOffer` row is not deletable" in normalized
    assert 'DeleteOffer("device.grant.delete", SELF, OwnerBinding(...))' \
        in ledger
    assert "This exact action masks only that invite; it does not create a " \
        "terminal `DevicePrincipal` tombstone" in normalized
    assert "legacy `facts/content/delete.py` handler" in normalized
    assert "TRANSITION POLICY" in delete_handler
    assert "until the coordinated S5" in delete_handler
    assert "docs leave it open" not in delete_handler
    assert "MAX_LEGACY_ACTOR_ADMISSION_RECORD_BYTES = 8 * 1024" in ledger
    assert "MAX_LEGACY_ACTOR_ADMISSION_COMMIT_ROW_BYTES = 8 * 1024" in ledger
    assert "MAX_LEGACY_ACTOR_ADMISSION_PROOF_SLOT_BYTES = 512" in ledger
    assert "MAX_LEGACY_ACTOR_ADMISSION_COMMIT_PROOF_BYTES = 4 * 1024" in ledger
    assert "S4ActorAdmissionCapacityEnvelope(" in ledger
    assert "S4ActorAdmissionCapacityCell[" in ledger
    assert "S4ActorAdmissionScratchSlot(" in ledger
    assert "legacy_actor_admission_scratch_record_objects" in ledger
    assert "legacy_actor_admission_scratch_record_bytes" in ledger
    assert "legacy_actor_admission_scratch_write_leases" in ledger
    assert "COMMITTED_COPYING(attempt_id, " \
        "legacy_actor_admission_commit_id" in ledger
    assert "legacy_actor_admission_commit_proof_write_leases" in ledger
    assert "cutover_legacy_actor_admission_service_rows" in ledger
    assert "target CAS verifies the sealed scratch record, atomically " \
        "publishes the target, debits the disjoint canonical dimensions in " \
        "`S4ActorAdmissionCapacityCell`" in normalized
    assert "A failed CAS leaves the canonical capacity cell unchanged" \
        in normalized
    assert "generation-fenced scratch record is reclaimed only after every " \
        "write lease drains" in normalized
    assert "scratch and the canonical record can coexist until the canonical " \
        "hash/size is verified" in normalized
    assert "old delegated-admin grant with a removed grantor is never guessed " \
        "into or out of existence" in normalized
    assert "preexisting provider or an alternate closure" in normalized
    assert "commit the applicable bounded or paged evidence at a separate " \
        "earlier frontier" in normalized
    assert "uncommitted or prospective closure is never placed in an actor " \
        "record" in normalized
    assert "S4AuthorityProofCapacityEnvelope(" in ledger
    assert "S4AuthorityProofCapacityCell[" in ledger
    assert "S4AuthorityProofScratchSlot(" in ledger
    assert "s4_authority_proof_scratch_objects" in ledger
    assert "s4_authority_proof_scratch_bytes" in ledger
    assert "s4_authority_proof_scratch_write_leases" in ledger
    assert "A losing proof CAS debits no\ncanonical dimension" in ledger
    assert "PAGED_S4(S4PagedAuthorityAdmissionRef)" in ledger
    assert "CommittedS4PagedAuthorityProof[" in ledger
    assert "S4PagedAuthorityProofCommitProof[" in ledger
    assert "before any target may cite it" in normalized
    assert "not a future checkpoint placeholder" in normalized
    assert "pre-recorder provider whose one-time guard is now removed blocks " \
        "migration/requires re-anchor" in normalized
    assert "legacy_authority_checkpoint_namespace =" in ledger
    assert "LegacyAuthorityCheckpoint(legacy_authority_checkpoint_namespace," \
        in ledger
    assert "replaces `cutover_digest` in checkpoint identity" in normalized
    assert "LegacyAuthorityCheckpoint(cutover_digest" not in ledger
    assert "LegacyActorAuthorityTransport =" in ledger
    assert "recorded_actor_authority_ref(" in ledger
    assert "transport_actor_authority_ref(" in ledger
    assert "recorded paged ref and checkpoint transport ref are deliberately " \
        "not\nbyte-equal" in ledger
    assert "checkpoint ref is not required or permitted\n" \
        "                to equal the earlier recorded ref" in ledger
    assert "source-to-transport\n" \
        "                translation" in ledger
    assert "13 times 17 pages" in epic_contract
    assert "8 times 17 pages" not in epic_contract
    assert "13 keys times 17 pages" in contracts[4]
    assert "8 keys times 17 pages" not in contracts[4]
    assert "grantee-only continuing liveness" in contracts[4]
    assert "review-corrected" in contracts[4]
    assert "admission-time LegacyActorAdmissionRecord" in contracts[4]
    assert "bare device_invite cannot create DevicePrincipal" in contracts[4]
    assert "admin(D) remains key-scoped" in contracts[4]
    assert "ActionAuthorization" in contracts[4]
    assert "S4_DEVICE_INVITE_ACCEPTANCE" in contracts[4]
    assert "legacy_authority_checkpoint_namespace" in contracts[4]
    assert "pre-recorder delegated-admin" in contracts[4]
    assert "GRANDFATHER" in contracts[4]
    assert "on-demand authority closure" in contracts[4]
    assert "CHECKPOINT transport" in contracts[4]
    assert "ActionAuthorization verification is action-scoped" in contracts[4]
    assert "Proposal/support proof refs plus the service-derived " \
        "ActionAuthorization determine proof_digest" in contracts[4]
    assert "DELETE_OWNER or NEVER" in contracts[2]
    assert "bare device_invite is never a DevicePrincipal target" \
        in contracts[2]
    assert "device.grant.delete" in contracts[2]
    assert "roots its exact DeleteOffer/OwnerBinding" in contracts[5]
    assert "LegacyActorAdmissionRecord" in contracts[5]
    assert "S4ActorAdmissionCapacityEnvelope" in contracts[5]
    assert "losing CAS" in contracts[5]
    assert "S4ActorAdmissionScratchSlot" in contracts[5]
    assert "disjoint scratch plus canonical coexistence" in contracts[5]
    assert "proposal/support proof refs plus the service-derived " \
        "ActionAuthorization determine proof_digest and the signed receipt" \
        in contracts[6]
    assert "permits primary device bootstrap and later direct rejoin" \
        in contracts[6]
    assert "explicit KEY or OWNER admin scope" in contracts[6]
    assert "ordinary cross-user denial" in contracts[7]
    assert "pre-tombstone" in contracts[7]
    assert "migrate checkpointable deep owner proofs" in contracts[10]
    assert "target-key-signed DeviceOwnerConsent" in contracts[10]
    assert "admission-time actor record" in contracts[10]
    assert "current-winner-substituted evidence" in contracts[10]
    assert "PAGED_S4(S4PagedAuthorityAdmissionRef)" in contracts[10]
    assert "before the target CAS" in contracts[10]
    assert "136-page ordinary insertion" not in contracts[10]
    assert "221-page ordinary insertion" in contracts[10]


def test_s4_recorded_authority_survives_cutover_and_fallback_retries():
    """Recorded proof identity and canonical quota cannot reset at cutover."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    normalized = " ".join(ledger.split())
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = " ".join(
        " ".join(strings(issues[f"{RECOVERY_EPIC}.{stage}"]))
        for stage in (4, 5, 6, 10)
    )

    paged_ref = re.search(
        r"S4PagedAuthorityAdmissionRef =\s+canon\("
        r"provider_fact_key, provider_fid, provider_fact_record_oid,\s+"
        r"legacy_authority_proof_record_oid,\s+"
        r"s4_paged_authority_proof_commit_id,\s+"
        r"s4_paged_authority_proof_commit_proof_oid\)",
        ledger,
    )
    assert paged_ref
    assert "paged_ref.s4_paged_authority_proof_commit_proof_oid]) equals" \
        in ledger
    assert "paged_ref.s4_paged_authority_proof_commit_id]) equals" not in ledger
    assert "retains both the strong commit id and the content-addressed " \
        "commit-proof oid" in normalized
    assert "MAX_S4_PAGED_AUTHORITY_PROOF_COMMIT_ROW_BYTES = 4 * 1024" \
        in ledger
    assert "MAX_S4_PAGED_AUTHORITY_PROOF_SLOT_BYTES = 512" in ledger
    assert "MAX_S4_PAGED_AUTHORITY_PROOF_COMMIT_PROOF_BYTES = 4 * 1024" \
        in ledger
    assert "S4PagedAuthorityProofSlot[" in ledger
    assert "FILLED(\n                    " \
        "paged_ref.s4_paged_authority_proof_commit_proof_oid)" in ledger
    assert "restart\nrecomputes the same proof and oid" in ledger
    assert "MAX_S4_AUTHORITY_PROOF_CAPACITY_ENVELOPE_BYTES = 4 * 1024" \
        in ledger
    assert "MAX_S4_ACTOR_ADMISSION_CAPACITY_ENVELOPE_BYTES = 4 * 1024" \
        in ledger
    assert "MAX_S4_AUTHORITY_PROOF_CAPACITY_CELL_BYTES = 4 * 1024" in ledger
    assert "MAX_S4_ACTOR_ADMISSION_CAPACITY_CELL_BYTES = 4 * 1024" in ledger
    assert "MAX_S4_AUTHORITY_PROOF_SCRATCH_SLOT_BYTES = 4 * 1024" in ledger
    assert "MAX_S4_ACTOR_ADMISSION_SCRATCH_SLOT_BYTES = 4 * 1024" in ledger

    assert "The row's `CommitBinding` is immutable" in ledger
    assert "AuthorityProofCommitProof[authority_proof_commit_id] =" in ledger
    assert "keeps its historical\n`DirectRoot` row and post-commit proof " \
        "through cutover" in ledger
    assert "never rewrites or recommits an\nexisting `DirectRoot` row as " \
        "`CutoverGeneration`" in ledger
    assert "row presence is never\nmisclassified as “uncommitted”" in ledger
    assert "Cutover blocks on that recovery instead of attempting a second " \
        "generation-bound\nrow" in ledger
    assert "a `CutoverGeneration` replacement for a\n   `DirectRoot` row, " \
        "aborts migration" in ledger
    assert "an exact proof closure committed before the fence keeps its " \
        "historical `DirectRoot` row" in normalized

    assert "s4_authority_proof_capacity_cell_id =\n" \
        '    H("s4-authority-proof-capacity-cell", workspace)' in ledger
    assert "S4AuthorityProofCapacityCell[" \
        "s4_authority_proof_capacity_cell_id] =" in ledger
    assert "s4_actor_admission_capacity_cell_id =\n" \
        '    H("s4-actor-admission-capacity-cell", workspace)' in ledger
    assert "S4ActorAdmissionCapacityCell[" \
        "s4_actor_admission_capacity_cell_id] =" in ledger
    assert "S4AuthorityProofCapacityCell(\n    workspace, s4_generation" \
        not in ledger
    assert "S4ActorAdmissionCapacityCell(\n    workspace, s4_generation" \
        not in ledger
    assert "`s4_generation` is deliberately absent from their keys" in ledger
    assert "initialized\nexactly once" in ledger
    assert "s4_authority_proof_capacity_envelope_objects" in ledger
    assert "s4_actor_admission_capacity_envelope_objects" in ledger
    assert "s4_authority_proof_capacity_cell_rows" in ledger
    assert "s4_actor_admission_capacity_cell_rows" in ledger
    assert "s4_paged_authority_proof_slot_rows" in ledger
    assert "a bare oid, collected preimage or\nunbudgeted cell cannot certify " \
        "a balance" \
        in ledger
    assert "A retry may reset\nonly the drained scratch state" in ledger
    assert "canonical capacity balance" in normalized
    assert "workspace-global canonical capacity balance" in normalized
    assert "canonical balances are workspace-global" in contracts
    assert "paged proof oid" in contracts
    assert "DirectRoot" in contracts
    assert "S4PagedAuthorityProofSlot" in contracts
    assert "capacity cells have deterministic ids" in contracts
    assert "explicit cell/slot row-and-byte charges" in contracts


def test_recovery_ledger_pins_history_independent_tree_shapes():
    """Equal logical states cannot diverge by insertion history or seed drift."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "H(layout_seed, tree_domain, logical_key)" in ledger
    assert "logical key/value set plus the workspace\n`layout_seed` determines" \
        in ledger
    assert "forward, reverse, randomized, one-by-one and bulk" in ledger
    assert "MAX_LAYOUT_SEED_TRIALS = 1024" in ledger
    assert "the seed never changes" in ledger
    assert "ordinary structural insertion whose actual prospective B-treap " \
        "mutation exceeds a cap rejects" in " ".join(ledger.split())
    assert "A later\nremoval changes only fixed-width values at already " \
        "present keys" in ledger
    logical_rows = ledger.index(
        "The pre-action\n   `legacy_universe_rows_digest`"
    )
    basis = ledger.index("cutover_basis_digest =", logical_rows)
    candidate_seed = ledger.index(
        'H("layout-seed", anchor, cutover_basis_digest, trial)',
        basis,
    )
    universe_root = ledger.index("legacy_universe_map_root", candidate_seed)
    final_cutover = ledger.index(
        'H("s5-cutover", cutover_basis_digest',
        universe_root,
    )
    assert logical_rows < basis < candidate_seed < universe_root < final_cutover
    assert "H(anchor, cutover_digest, trial)" not in ledger
    assert "contain no B-treap root or\nseed" in ledger
    assert '"layout_seed": <32-byte canonical B-treap seed>' in ledger
    assert "every later\nroot must repeat it byte-for-byte" in ledger
    assert "origin_publisher_id` is the lexicographically lowest\n" \
        "   registered publisher id" in ledger
    assert "opposite publisher-enumeration orders produce identical logical " \
        "rows and\n   `legacy_universe_rows_digest`" in ledger
    old_sources = ledger.index("old_slot_globals_digest` and:")
    mask_namespace = ledger.index("legacy_mask_namespace =", old_sources)
    census = ledger.index(
        "Still before constructing any migrated `FactRecord`",
        mask_namespace,
    )
    census_digest = ledger.index(
        "`legacy_effect_census_digest`",
        census,
    )
    masked_records = ledger.index(
        "every required migration-only selector\n   is fixed before its "
        "victim's migrated FactRecord is hashed",
        census_digest,
    )
    assert (
        old_sources
        < mask_namespace
        < census
        < census_digest
        < masked_records
        < logical_rows
    )
    assert "LegacyMask(cutover_digest" not in ledger
    assert "Migration(cutover_digest" not in ledger


def test_migration_retains_the_frozen_root_and_effect_census():
    """Restart certification cannot depend on garbage-collected S4 pages."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    normalized = " ".join(ledger.split())

    freeze = ledger.index("It freezes the exact canonical root bytes as")
    namespace = ledger.index("legacy_mask_namespace =", freeze)
    census = ledger.index(
        "Still before constructing any migrated `FactRecord`",
        namespace,
    )
    records = ledger.index(
        "then materializes that exact **logical row set**",
        census,
    )
    assert freeze < namespace < census < records
    assert "reconciled_s4_root_oid = H(reconciled_s4_root)" in ledger
    assert "legacy_effect_census_oid" in ledger
    assert "legacy_effect_census_objects, legacy_effect_census_bytes" in ledger
    assert "reconciled_s4_root_objects, reconciled_s4_root_bytes" in ledger
    assert '"legacy_effect_census": <LegacyEffectCensus oid or EMPTY>' in ledger
    assert (
        "`LegacyMigrationSeal` binds the `cutover_digest`, "
        "`reconciled_s4_root_oid`, `legacy_mask_namespace`, "
        "`legacy_authority_checkpoint_namespace`, "
        "`legacy_effect_census_oid`, `legacy_effect_census_digest`"
    ) in normalized
    assert (
        "fetches and reassembles the retained S4 root bytes, and requires "
        "their "
        "content hash to equal `reconciled_s4_root_oid`"
    ) in normalized
    assert (
        "uses only the S5 codec to fetch the complete "
        "`legacy_effect_census_oid` closure"
    ) in normalized
    assert "LegacyTranslationAttestation" in ledger
    assert "No post-seal code path imports or retains the S4 decoder" in ledger
    assert "decodes that exact canonical S4 root off-request" not in ledger
    assert "`MAX_ROOT_BYTES` is an S5 request-path\nroot limit" in ledger
    assert "drop-reconciled-s4-root" in ledger
    assert "post-seal-s4-decoder-dependency" in ledger
    assert "late-legacy-mask-selector" in ledger


def test_recovery_ledger_isolates_migration_writers_and_content_quota():
    """Legacy writers and payload exhaustion cannot consume revocation space."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))

    assert "meta-s5/<workspace>/<cutover_digest>/" in ledger
    assert "rotates/revokes every legacy publisher metadata-write credential" \
        in ledger
    migration = ledger.index("S5 starts with a **grandfather/backfill barrier")
    fallback = ledger.index(
        "inactive service-only S4 fallback generation above",
        migration,
    )
    writer_drain = ledger.index(
        "definitively drains every\n   write admitted before the fence",
        migration,
    )
    snapshot = ledger.index(
        "Only after that physical writer/drain barrier",
        writer_drain,
    )
    logical_rows = ledger.index(
        "legacy_universe_rows_digest",
        snapshot,
    )
    abort = ledger.index(
        "Any failure after the legacy-writer fence but before the first S5 "
        "root CAS",
        logical_rows,
    )
    assert migration < fallback < writer_drain < snapshot < logical_rows < abort
    assert "A delayed or ambiguous pre-fence write keeps\n" \
        "   the barrier open" in ledger
    assert "No old-prefix write can settle between this enumeration and the " \
        "S5 CAS" in " ".join(ledger.split())
    assert "LegacyIamAttestation" in ledger
    assert "missing, redirected, oversized or\n   bare-digest substitute" \
        in ledger
    assert "a backend that\n   cannot attest this cut cannot migrate in place" \
        in ledger
    assert "ordinary S4 publication resumes through the service" in ledger
    assert "never re-enables an old publisher credential" in ledger
    assert "checkpoint, canonical-key, seed-trial, capacity, object-write, " \
        "final-IAM-attestation and certification failure" \
        in " ".join(ledger.split())
    assert "Existing 16-digit-positive facts are the\nnamed regression" \
        in ledger
    assert "ContentCapacityEnvelope(content_objects, content_bytes, " \
        "content_attempts," in ledger
    assert "PendingCapacityEnvelope(staging_slots, staging_bytes, " \
        "staging_write_leases)" in ledger
    assert "each envelope has a distinct bucket/binding or an enforceable\n" \
        "provider quota boundary" in ledger
    assert "Direct admission bypasses a full optional pending pool" in ledger
    assert "IAM-isolated metadata namespace" in cutover
    assert "content quota exhaustion" in cutover.lower()
    assert "pending quota exhaustion" in cutover.lower()


def test_cutover_pins_snapshot_values_only_after_the_frozen_snapshot():
    """Pre-fence trust cannot name a seed or namespace that does not exist yet."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    bootstrap = ledger.index(
        "MigrationBootstrapCommitment(workspace, admission_pk"
    )
    no_derived_values = ledger.index(
        "deliberately contains **no** `layout_seed`",
        bootstrap,
    )
    writer_drain = ledger.index(
        "definitively drains every\n   write admitted before the fence",
        bootstrap,
    )
    snapshot = ledger.index(
        "Only after that physical writer/drain barrier",
        writer_drain,
    )
    logical_rows = ledger.index(
        "legacy_universe_rows_digest",
        snapshot,
    )
    final_binding = ledger.index(
        "materializes and service-signs the post-snapshot `S5CutoverBinding`",
        logical_rows,
    )
    assert (
        bootstrap
        < no_derived_values
        < writer_drain
        < snapshot
        < logical_rows
        < final_binding
    )
    assert re.search(r"pre-pinned\s+`admission_pk`", ledger)
    assert '"cutover_binding": <S5CutoverBinding oid or EMPTY>' in ledger
    assert "`migration_bootstrap_oid`, `capacity_ceiling_oid`" in ledger
    assert "`legacy_source_ceiling_oid`, `s5_cutover_binding_oid`" in ledger
    assert "capacity_ceiling_oid, pending_capacity_digest" in ledger
    assert "capacity_ceiling_digest" not in ledger
    assert "content-hash-roots the complete canonical `CapacityCeiling`" \
        in ledger
    assert "decodes its\n   canonical vector and proves the exact " \
        "`CapacityEnvelope` componentwise" in ledger
    assert "MAX_CAPACITY_CEILING_BYTES = 8 * 1024" in ledger
    assert "MAX_LEGACY_SOURCE_CEILING_BYTES = 4 * 1024" in ledger
    assert "capacity_ceiling_objects, capacity_ceiling_bytes" in ledger
    assert "legacy_source_ceiling_objects, legacy_source_ceiling_bytes" \
        in ledger
    assert "CapacityCeiling" in contracts
    assert "MigrationBootstrapCommitment" in contracts
    assert "S5CutoverBinding" in contracts
    assert "pre-fence commitment contains no snapshot-derived" in cutover
    assert "pre-fence-final-binding" in integration


def test_each_cutover_retry_prepares_a_fresh_writable_fallback():
    """Consecutive aborts never fence the only remaining S4 writer."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    shadow = "\n".join(strings(issues[f"{RECOVERY_EPIC}.5"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    abort = ledger.index(
        "Any failure after the legacy-writer fence but before the first S5 "
        "root CAS"
    )
    retry = ledger.index(
        "A later S5 retry is a **new migration attempt**",
        abort,
    )
    successor = ledger.index(
        "another inactive fresh service-only S4 fallback generation",
        retry,
    )
    fence = ledger.index(
        "Only after all\nof those steps succeed may it fence the currently "
        "active generation",
        successor,
    )
    repeated = ledger.index(
        "each of any number of consecutive\npre-CAS aborts has a distinct "
        "already-provisioned successor",
        fence,
    )
    assert abort < retry < successor < fence < repeated
    assert "fresh\n`MigrationBootstrapCommitment` naming that successor" \
        in ledger
    assert "at least two consecutive post-fence/pre-CAS\n  failures" in ledger
    assert "All bootstrap/fallback generation ids are distinct and monotonic" \
        in ledger
    assert "fresh bootstrap/fallback" in shadow
    assert "two consecutive post-fence/pre-CAS aborts" in cutover
    assert "reuse-active-fallback-on-retry" in integration


def test_first_s5_root_has_disjoint_whole_corpus_staging_capacity():
    """The atomic migration cannot borrow a later one-operation scratch pool."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    contracts = "\n".join(strings(issues[f"{RECOVERY_EPIC}.4"]))
    shadow = "\n".join(strings(issues[f"{RECOVERY_EPIC}.5"]))
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    source = re.search(
        r"LegacySourceCeiling\((.*?)\)\nCutoverCapacityEnvelope",
        ledger,
        re.DOTALL,
    )
    staging = re.search(
        r"CutoverCapacityEnvelope\((.*?)\)\n```",
        ledger,
        re.DOTALL,
    )
    assert source is not None
    assert staging is not None
    assert {
        "published_objects",
        "published_bytes",
        "registered_quarantine_objects",
        "registered_quarantine_bytes",
        "unsettled_old_write_objects",
        "unsettled_old_write_bytes",
    } <= set(re.findall(r"[a-z_]+", source.group(1)))
    assert {
        "cutover_manifest_rows",
        "cutover_manifest_bytes",
        "cutover_staging_objects",
        "cutover_staging_bytes",
        "cutover_staging_write_leases",
        "cutover_content_pin_set_objects",
        "cutover_content_pin_set_bytes",
        "cutover_content_pin_generation_rows",
        "cutover_content_pin_generation_bytes",
        "cutover_content_pin_anchor_rows",
        "cutover_content_pin_anchor_bytes",
        "cutover_service_staging_rows",
        "cutover_service_staging_bytes",
    } <= set(re.findall(r"[a-z_]+", staging.group(1)))
    assert re.search(r"complete\s+`CutoverObjectManifest`", ledger)
    assert "paged `CutoverServiceManifest`" in ledger
    assert "protocol-pinned `MigrationSizer`" in ledger
    assert "assumes\n   no favorable deduplication" in ledger
    assert "cutover-service/<workspace>/<service_generation_id>/" \
        "<logical-table>/<logical-key>" in ledger
    assert "MAX_CUTOVER_SERVICE_BATCH_ROWS = 128" in ledger
    assert "MAX_CUTOVER_SERVICE_BATCH_BYTES = 1 * 1024 * 1024" in ledger
    assert "MAX_CUTOVER_ACTIVATION_ROWS = 8" in ledger
    assert "MAX_CUTOVER_ACTIVATION_BYTES = 128 * 1024" in ledger
    assert "bounded **activation**, not a replay of the\n   workspace-sized " \
        "row plan" in ledger
    assert "pointer flip makes\n   the complete pre-staged " \
        "registry/admission state visible" in ledger
    assert "cutover_payload_manifest_digest" in ledger
    assert "CutoverPayloadManifest(object_manifest_root_oid" in ledger
    assert "CommitBinding = CutoverGeneration(service_generation_id)" in ledger
    assert "CutoverCommitAnchor" in ledger
    assert "CutoverContentPinSet" in ledger
    assert "CutoverContentPinGeneration" in ledger
    assert "CutoverContentPinAnchor" in ledger
    assert "MAX_CUTOVER_CONTENT_PIN_GENERATION_BYTES = 8 * 1024" in ledger
    assert "MAX_CUTOVER_CONTENT_PIN_ANCHOR_BYTES = 8 * 1024" in ledger
    assert "No hash in the descriptor or payload includes that tail" in ledger
    assert "one ordinal per\n   preprovisioned object slot" in ledger
    assert re.search(r"first root is\s+therefore one atomic cut", ledger)
    assert "post-cutover, single-operation" in ledger
    assert "It is never used to stage the first S5 root" in ledger
    assert "migration_bootstrap_objects, migration_bootstrap_bytes" in ledger
    assert "s5_cutover_binding_objects, s5_cutover_binding_bytes" in ledger
    assert "capacity_ceiling_objects, capacity_ceiling_bytes" in ledger
    assert "legacy_source_ceiling_objects, legacy_source_ceiling_bytes" \
        in ledger
    assert "cutover_service_generation_objects, " \
        "cutover_service_generation_bytes" in ledger
    assert '"service_generation": <CutoverServiceGeneration oid or EMPTY>' \
        in ledger
    assert "After restart and reachability GC, a new certifier fetches both " \
        "retained preimages" in " ".join(ledger.split())
    assert "digest-only-capacity-ceiling" in integration
    assert "LegacySourceCeiling" in contracts
    assert "CapacityCeiling" in contracts
    assert "CutoverCapacityEnvelope" in contracts
    assert "CutoverServiceGeneration" in contracts
    assert "whole-cutover capacity preflight" in shadow
    assert "complete first-root manifest" in cutover
    assert "single-operation-cutover-scratch" in integration
    assert "workspace-sized-service-row-plan" in integration
    assert "cyclic-cutover-generation-manifest" in integration
    assert "root-bound-grandfather-row" in integration
    assert "root-keyed-cutover-certificate-reservation" in integration
    assert "active generation's service rows" in ledger


def test_recovery_ledger_never_walks_descendants_to_release_escrow():
    """Ancestor suppression remains bounded even with enormous fan-out."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "does not enumerate descendants" in ledger
    assert "does not release their individual escrow" in ledger
    assert "O(action) work regardless of descendant count" in ledger
    assert "LiabilityReleaseCheckpoint" in ledger
    assert "neither revocation\nsuccess nor ordinary capacity may assume" \
        in ledger


def test_action_slots_point_to_bounded_out_of_line_records():
    """Maximum target and evidence stay rooted out of line within their cap."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    fact_ts_max = 999_999_999_999_999
    target_spec = {
        "ExactSids": [
            {
                "target_fact_key": f"{fact_ts_max:015d}:{index:064x}",
                "target_fact_record_oid": f"{index + 200:064x}",
                "selector_token": "SELF",
                "resolved_sid": f"fact:{index:064x}",
            }
            for index in range(32)
        ],
    }
    encoded_target = json.dumps(
        target_spec,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    proof_refs = [
        {
            "role": "proposal" if index == 0 else "support",
            "fact_key": f"{fact_ts_max:015d}:{index + 32:064x}",
            "fid": f"{index + 32:064x}",
            "fact_record_oid": f"{index + 132:064x}",
        }
        for index in range(7)
    ]
    receipt_ref = {
        "role": "receipt",
        "fact_key": f"{fact_ts_max:015d}:{39:064x}",
        "fid": f"{39:064x}",
        "fact_record_oid": f"{139:064x}",
    }
    evidence_refs = proof_refs + [receipt_ref]
    encoded_action = json.dumps(
        {"target_spec": target_spec, "evidence_refs": evidence_refs},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    fact_keys = [
        binding["target_fact_key"]
        for binding in target_spec["ExactSids"]
    ] + [ref["fact_key"] for ref in evidence_refs]

    assert len(encoded_target) > 512
    assert len(encoded_action) < 16 * 1024
    assert len(fact_keys) == len(set(fact_keys)) == 40
    assert all(len(key.encode()) == 80 for key in fact_keys)
    assert all(
        re.fullmatch(r"[0-9]{15}:[0-9a-f]{64}", key)
        for key in fact_keys
    )
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", binding["target_fact_record_oid"])
        for binding in target_spec["ExactSids"]
    )
    assert len(proof_refs) == 7
    assert len(evidence_refs) == 8
    assert "FACT_TS_MIN           = 0" in ledger
    assert "FACT_TS_MAX           = 999999999999999" in ledger
    assert "MAX_FACT_KEY_BYTES    = 80" in ledger
    assert "integer but not a boolean" in ledger
    assert "Negative, 16-digit positive, signed,\nwhitespace-padded and " \
        "ambiguous-colon forms reject" in ledger
    assert "MAX_ACTION_RECORD_BYTES = 16 * 1024" in ledger
    assert "MAX_ADMISSION_PROOF_REFS = 7" in ledger
    assert "MAX_ACTION_EVIDENCE_REFS = 8" in ledger
    assert "seven-record input whose canonical bytes total\n  " \
        "`MAX_ADMISSION_PROOF_BYTES` plus maximum framing fits the 64 KiB" \
        in ledger
    assert "one more input byte rejects before receipt signing" in ledger
    assert re.search(
        r"Filling a slot stores only\s+fixed-width "
        r"`FILLED\(action_record_oid\)`",
        ledger,
    )
    assert "EvidenceRef(role, f)" in ledger
    assert "FactRecord[ref.fact_record_oid].raw_root_oid roots" in ledger
    assert "FactRecord[b.target_fact_record_oid] has key " \
        "b.target_fact_key" in ledger
    assert "ActionRecord makes each named target FactRecord and its " \
        "raw-root closure\nindependently reachable" in ledger
    assert "target later\nleaves the current eligible proof DAG for " \
        "canonical-provider quarantine" in ledger
    assert "drop-target-record-after-quarantine" in ledger
    assert "action-specific canonical reachability path after sync, restart " \
        "and GC" in ledger
    assert "Worker never fetches it" in ledger


def test_principal_provider_registry_retains_bounded_record_bindings():
    """Every terminal-principal provider remains provable after quarantine."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    fact_ts_max = 999_999_999_999_999
    bindings = [
        {
            "provider_fact_key": f"{fact_ts_max:015d}:{index:064x}",
            "provider_fact_record_oid": f"{index + 100:064x}",
            "provider_fid": f"{index:064x}",
        }
        for index in range(64)
    ]
    encoded = json.dumps(
        {"principal_provider_bindings": bindings},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    assert len(bindings) == 64
    assert len(encoded) < 32 * 1024
    assert all(len(binding["provider_fact_key"].encode()) == 80
               for binding in bindings)
    assert len({binding["provider_fid"] for binding in bindings}) == 64
    assert "PrincipalProviderBinding(\n    provider_fact_key, " \
        "provider_fact_record_oid, provider_fid)" in ledger
    assert "Each binding is an authenticated reachability edge to the exact " \
        "FactRecord and\nits raw-root closure, not a bare fid" in ledger
    assert "A provider leaving the current eligible proof DAG for\n" \
        "canonical-provider quarantine does not delete its FactTree row or " \
        "registry\nbinding" in ledger
    assert "Restore must match the exact\nretained binding and consumes no " \
        "new count" in ledger
    assert "FactRecord[p.provider_fact_record_oid].fid = p.provider_fid" \
        in ledger
    assert "principal-provider-bare-fid-after-quarantine" in ledger
    assert "including when earlier providers are quarantined rather than " \
        "live" in ledger


def test_authority_candidates_root_bounded_proof_preimages():
    """Fallback certification has exact support bytes, not only a digest."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    fact_ts_max = 999_999_999_999_999
    bindings = [
        {
            "fact_key": f"{fact_ts_max:015d}:{index:064x}",
            "fid": f"{index:064x}",
            "fact_record_oid": f"{index + 100:064x}",
        }
        for index in range(64)
    ]
    edges = [
        {
            "dependent_binding_index": dependent,
            "dependency_kind": "REF",
            "dependency_ordinal": 0,
            "provider_binding_index": dependent - 1,
        }
        for dependent in range(1, 64)
    ] + [
        {
            "dependent_binding_index": dependent,
            "dependency_kind": "NEED",
            "dependency_ordinal": 0,
            "provider_binding_index": dependent - 2,
        }
        for dependent in range(2, 64)
    ] + [
        {
            "dependent_binding_index": dependent,
            "dependency_kind": "REF",
            "dependency_ordinal": 1,
            "provider_binding_index": 0,
        }
        for dependent in (3, 4, 5)
    ]
    edges = sorted(
        edges,
        key=lambda edge: (
            edge["dependent_binding_index"],
            edge["dependency_kind"],
            edge["dependency_ordinal"],
            edge["provider_binding_index"],
        ),
    )
    proof_closure_digest = hashlib.sha256(json.dumps(
        {"fact_bindings": bindings, "proof_edges": edges},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()).hexdigest()
    record = {
        "provider_binding_index": 63,
        "sorted_fact_bindings": bindings,
        "sorted_proof_edges": edges,
        "proof_closure_digest": proof_closure_digest,
        "transport_proof_depth": 63,
        "logical_proof_depth": 63,
        "canonical_transport_cost": len(edges),
        "sorted_checkpoint_fids": [],
    }
    encoded = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    proof_record_oid = hashlib.sha256(encoded).hexdigest()
    provider_fid = bindings[record["provider_binding_index"]]["fid"]
    candidate_preimage = json.dumps(
        {
            "domain": "authority-candidate",
            "need_key": ["member", "alice", "ANY", [], "member-v1"],
            "provider_fid": provider_fid,
            "authority_proof_record_oid": proof_record_oid,
            "proof_closure_digest": record["proof_closure_digest"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    candidate_id = hashlib.sha256(candidate_preimage).hexdigest()
    canonical_candidate_rank = (
        record["logical_proof_depth"],
        provider_fid,
        candidate_id,
    )

    assert len(bindings) == 64
    assert len(edges) == 128
    assert len({
        (
            edge["dependent_binding_index"],
            edge["dependency_kind"],
            edge["dependency_ordinal"],
            edge["provider_binding_index"],
        )
        for edge in edges
    }) == len(edges)
    assert all(
        edge["provider_binding_index"] < edge["dependent_binding_index"]
        for edge in edges
    )
    assert len(encoded) < 64 * 1024
    assert "candidate_id" not in record
    assert "canonical_candidate_rank" not in record
    assert canonical_candidate_rank[-1] == candidate_id
    assert all(len(binding["fact_key"].encode()) == 80
               for binding in bindings)
    assert "MAX_AUTHORITY_PROOF_FACTS = 64" in ledger
    assert "MAX_AUTHORITY_PROOF_EDGES = 128" in ledger
    assert "MAX_AUTHORITY_PROOF_RECORD_BYTES = 64 * 1024" in ledger
    normalized_ledger = " ".join(ledger.split())
    assert "The full and base candidate-registry values root each proof " \
        "record, which roots every support FactRecord/raw closure" \
        in normalized_ledger
    assert "not another bare digest or an invitation to search\nFactTree" \
        in ledger
    assert "ADMITTED_PROOF" in ledger
    assert "CLEAR | MASKED(witness_action_slot)" in ledger
    assert "COOFFERS_MATCH | COOFFERS_MISMATCH" in ledger
    assert "bare-authority-proof-digest" in ledger
    assert "drop-authority-proof-support-after-quarantine" in ledger
    assert "The candidate-id tie breaker is deliberately outside " \
        "`AuthorityProofRecord`" in ledger
    assert "authority-proof-candidate-id-cycle" in ledger
    assert "transport_proof_depth, logical_proof_depth" in ledger
    assert "MAX_LOGICAL_PROOF_DEPTH = 2**63 - 1" in ledger
    assert "authority_proof_commit_id =" in ledger
    assert "AuthorityProofCommitProof[authority_proof_commit_id] =" in ledger


def test_need_keys_bind_complete_required_cooffers():
    """The same base need cannot alias different provider assertions."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    signer = "s" * 64

    def need_key(user):
        required = tuple(sorted({
            ("device", user, signer),
        }))
        return (
            "device_key",
            signer,
            "ANY",
            required,
            "device-invite-v1",
        )

    alice_need = need_key("a" * 64)
    bob_need = need_key("b" * 64)
    authority_value = (
        "p" * 64,
        "d" * 64,
        (63, "p" * 64, "c" * 64),
        64,
    )
    encode = lambda value: json.dumps(  # noqa: E731 - compact size oracle
        value, sort_keys=True, separators=(",", ":")
    ).encode()

    assert alice_need != bob_need
    assert alice_need[:3] == bob_need[:3]
    assert alice_need[-1] == bob_need[-1]
    assert len(encode(alice_need)) <= 320
    assert len(encode(authority_value)) <= 320
    assert len(encode((alice_need, authority_value))) <= 1024
    assert len(alice_need[3]) <= 4
    assert "RequiredCoOffer =" in ledger
    assert "sorted_unique(RequiredCoOffer...)" in ledger
    assert "MAX_REQUIRED_COOFFERS_PER_NEED = 4" in ledger
    assert "MAX_NEED_KEY_BYTES = 320" in ledger
    assert "MAX_AUTHORITY_TREE_VALUE_BYTES = 320" in ledger
    assert "MAX_TREE_ROW_BYTES    = 1024" in ledger
    assert "selection-before-requirement" in ledger
    assert "COOFFERS_MISMATCH`, AuthorityTree stores `NO_PROVIDER` rather " \
        "than skipping to\na losing candidate" in ledger
    assert "two `device_key` needs\nwith different user-specific required " \
        "`device` co-offers are different\nNeedKeys" in ledger
    assert "needkey-drops-required-cooffers" in ledger
    assert "unbounded-required-cooffers" in ledger


def test_base_offer_directory_updates_every_full_need_key():
    """A new provider reaches match and mismatch tuples without a tree scan."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    signer = "s" * 64

    def need_key(user):
        return (
            "device_key",
            signer,
            "ANY",
            (("device", user, signer),),
            "device-invite-v1",
        )

    def base_key(need):
        return need[0], need[1], need[2], need[4]

    alice = need_key("a" * 64)
    bob = need_key("b" * 64)
    charlie = need_key("c" * 64)
    directory = {base_key(alice): (alice, bob)}
    provider_offers = frozenset({("device", "a" * 64, signer)})

    def cooffers_match(need):
        return set(need[3]) <= provider_offers

    full_candidate_updates = {
        need: "COOFFERS_MATCH" if cooffers_match(need)
        else "COOFFERS_MISMATCH"
        for need in directory[base_key(alice)]
    }
    base_candidates = (provider_offers,)
    late_need_candidates = {
        offers: "COOFFERS_MATCH"
        if set(charlie[3]) <= offers else "COOFFERS_MISMATCH"
        for offers in base_candidates
    }

    assert base_key(alice) == base_key(bob) == base_key(charlie)
    assert full_candidate_updates == {
        alice: "COOFFERS_MATCH",
        bob: "COOFFERS_MISMATCH",
    }
    assert late_need_candidates == {provider_offers: "COOFFERS_MISMATCH"}
    assert "BaseOfferNeedKeyRegistry[(workspace, BaseNeedKey)]" in ledger
    assert "AuthorityBaseCandidateRegistry[(workspace, BaseNeedKey)]" in ledger
    assert "including tuples the provider\ndoes not satisfy" in ledger
    assert "appends the derived match/mismatch ref to\n   **every** listed " \
        "full candidate value" in ledger
    assert "a new full NeedKey never scans old\nproviders" in ledger
    assert "MAX_FULL_NEED_KEYS_PER_BASE = 64" in ledger
    assert "MAX_PROVIDER_BASES_PER_PUBLICATION = 8" in ledger
    assert "provider-scans-or-omits-full-needkeys" in ledger


def test_base_candidate_discovery_does_not_reuse_full_needkey_rank():
    """A base registry cannot carry a winner rank derived for one full key."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    provider_fid = "p" * 64
    alice_need = (
        "device_key",
        "signer",
        "ANY",
        (("device", "alice", "signer"),),
        "device-invite-v1",
    )
    bob_need = (
        "device_key",
        "signer",
        "ANY",
        (("device", "bob", "signer"),),
        "device-invite-v1",
    )
    proof_oids = tuple(
        hashlib.sha256(f"proof-{index}".encode()).hexdigest()
        for index in range(64)
    )

    def candidate_id(need_key, proof_oid):
        return hashlib.sha256(json.dumps(
            {
                "domain": "authority-candidate",
                "need_key": need_key,
                "provider_fid": provider_fid,
                "authority_proof_record_oid": proof_oid,
                "proof_closure_digest": proof_oid,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()).hexdigest()

    left, right = next(
        (left, right)
        for left in proof_oids
        for right in proof_oids
        if (
            candidate_id(alice_need, left)
            < candidate_id(alice_need, right)
        ) != (
            candidate_id(bob_need, left)
            < candidate_id(bob_need, right)
        )
    )
    alice_winner = min(
        (left, right), key=lambda proof: candidate_id(alice_need, proof)
    )
    bob_winner = min(
        (left, right), key=lambda proof: candidate_id(bob_need, proof)
    )
    base_schema = ledger.split(
        "AuthorityBaseCandidateRef(", 1
    )[1].split(
        "AuthorityBaseCandidateRegistry", 1
    )[0]

    assert alice_winner != bob_winner
    assert "candidate_id" not in base_schema
    assert "canonical_candidate_rank" not in base_schema
    assert "key=(provider_fid, authority_proof_record_oid," in ledger
    assert "The base order is only a\ncanonical set encoding; it is never " \
        "a winner order" in ledger
    assert "derive_full_candidate(NeedKey, base_ref)" in ledger
    assert "reuse-base-rank-for-full-needkey" in ledger


def test_late_needkey_reverse_fanout_is_bounded_in_both_arrival_orders():
    """Provider-first state cannot defer a 4,096-scope bill to a late key."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    disjoint_candidate_scopes = tuple(
        frozenset(
            f"scope:{candidate}:{scope}"
            for scope in range(64)
        )
        for candidate in range(64)
    )
    shared_scopes = frozenset(f"scope:{scope}" for scope in range(64))
    shared_candidate_scopes = (shared_scopes,) * 64

    def scope_union(candidate_scopes):
        return set().union(*candidate_scopes)

    old_per_candidate_check = all(
        len(scopes) <= 64 for scopes in disjoint_candidate_scopes
    )
    provider_first_union = scope_union(disjoint_candidate_scopes)
    need_first_union = scope_union(disjoint_candidate_scopes)
    legal_shared_union = scope_union(shared_candidate_scopes)

    assert old_per_candidate_check
    assert len(provider_first_union) == 4096
    assert provider_first_union == need_first_union
    assert len(provider_first_union) > 64
    assert len(legal_shared_union) == 64
    assert "MAX_AUTHORITY_IMPACT_SCOPES_PER_BASE = 64" in ledger
    assert "the same final provider set is\naccepted or rejected in both " \
        "arrival orders" in ledger
    assert "64 candidates with 64 disjoint scopes" in ledger
    assert "late-needkey-multiplies-candidate-scopes" in ledger


def test_legacy_checkpoint_preserves_source_candidate_order():
    """A shallow transport proof cannot promote a losing legacy provider."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    shallow_native = {
        "provider_fid": "b" * 64,
        "candidate_id": "1" * 64,
        "proof_depth": 2,
    }
    deep_legacy_source = {
        "source_fid": "a" * 64,
        "source_candidate_id": "2" * 64,
        "source_proof_depth": 519,
    }
    flattened_checkpoint = {
        "provider_fid": "0" * 64,
        "candidate_id": "0" * 64,
        "proof_depth": 0,
    }
    native_rank = (
        shallow_native["proof_depth"],
        shallow_native["provider_fid"],
        shallow_native["candidate_id"],
    )
    source_rank = (
        deep_legacy_source["source_proof_depth"],
        deep_legacy_source["source_fid"],
        deep_legacy_source["source_candidate_id"],
    )
    wrong_flattened_rank = (
        flattened_checkpoint["proof_depth"],
        flattened_checkpoint["provider_fid"],
        flattened_checkpoint["candidate_id"],
    )
    checkpoint_child = {
        "provider_fid": "c" * 64,
        "candidate_id": "3" * 64,
        "transport_proof_depth": 1,
        "logical_proof_depth": (
            deep_legacy_source["source_proof_depth"] + 1
        ),
    }
    native_competitor = (100, "b" * 64, "4" * 64)
    child_logical_rank = (
        checkpoint_child["logical_proof_depth"],
        checkpoint_child["provider_fid"],
        checkpoint_child["candidate_id"],
    )
    wrong_child_transport_rank = (
        checkpoint_child["transport_proof_depth"],
        checkpoint_child["provider_fid"],
        checkpoint_child["candidate_id"],
    )

    assert min((native_rank, source_rank)) == native_rank
    assert min((native_rank, wrong_flattened_rank)) == wrong_flattened_rank
    assert min((native_competitor, child_logical_rank)) == native_competitor
    assert min((native_competitor, wrong_child_transport_rank)) == \
        wrong_child_transport_rank
    assert "NATIVE_RANK | LEGACY_SOURCE_RANK(checkpoint_fid)" in ledger
    assert "(source_proof_depth, source_fid, source_candidate_id)" in ledger
    assert "flattening changes proof transport, not the canonical ordering" \
        in " ".join(ledger.lower().split())
    assert "The checkpoint's\n   short bounded proof depth, checkpoint fid " \
        "and service provider fid are\n   deliberately ineligible as " \
        "selection fields" in ledger
    assert "checkpoint-reranks-legacy-candidate" in ledger
    assert "DERIVED_LEGACY_RANK(sorted_checkpoint_fids)" in ledger
    assert "child of the\n   519-hop checkpoint has logical depth 520" in ledger
    assert "checkpoint-descendant-uses-transport-depth" in ledger


def test_legacy_inert_removals_never_gain_fact_slots():
    """A retained proposal absent from old effects stays evidence-only."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    universe = {
        "ordinary": ("PUBLISHED", "ORDINARY", "ordinary-record"),
        "effect": ("PUBLISHED", "EFFECT_SOURCE", "effect-record"),
        "duplicate": (
            "RETAINED_QUARANTINE",
            "EFFECT_EVIDENCE",
            "duplicate-record",
        ),
        "inert": (
            "RETAINED_QUARANTINE",
            "INERT_REMOVAL",
            "inert-record",
        ),
    }
    fact_tree = {
        fid: row[2]
        for fid, row in universe.items()
        if row[1] == "ORDINARY"
    }

    assert fact_tree == {"ordinary": "ordinary-record"}
    assert "LegacyDisposition =" in ledger
    assert "| EFFECT_SOURCE" in ledger
    assert "| EFFECT_EVIDENCE" in ledger
    assert "| INERT_REMOVAL" in ledger
    assert "No legacy removal\n   proposal receives an ordinary FactSlot" \
        in ledger
    assert "`INERT_REMOVAL` remains authenticated only by the frozen " \
        "universe map" in " ".join(ledger.split())
    assert "admit-inert-legacy-removal" in ledger


def test_legacy_checkpoints_bind_one_exact_source_closure():
    """Same-provider proof paths retain distinct checkpoint identities."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()

    def checkpoint(proof_digit, action_scope):
        proof_oid = proof_digit * 64
        closure_digest = chr(ord(proof_digit) + 1) * 64
        source_candidate_id = hashlib.sha256(
            (proof_oid + closure_digest).encode()
        ).hexdigest()
        return {
            "source_candidate_id": source_candidate_id,
            "source_fid": "a" * 64,
            "source_legacy_authority_proof_oid": proof_oid,
            "source_proof_closure_digest": closure_digest,
            "source_proof_depth": 519,
            "source_canonical_proof_cost": 519,
            "need_key": ["member", "alice", "ANY", [], "legacy-v1"],
            "selectors": ["fact:" + "a" * 64],
            "sorted_source_provider_sids": ["fact:" + "a" * 64],
            "sorted_source_action_scopes": [action_scope],
        }

    grantor_path = checkpoint("1", "MemberPrincipal(grantor)")
    grantee_path = checkpoint("2", "MemberPrincipal(grantee)")
    source_bindings = tuple(range(519))
    binding_pages = tuple(
        source_bindings[offset:offset + 64]
        for offset in range(0, len(source_bindings), 64)
    )
    encoded = {
        hashlib.sha256(json.dumps(
            item,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()).hexdigest()
        for item in (grantor_path, grantee_path)
    }

    assert len(encoded) == 2
    assert len(binding_pages) == 9
    assert max(map(len, binding_pages)) == 64
    assert grantor_path["source_fid"] == grantee_path["source_fid"]
    assert grantor_path["source_legacy_authority_proof_oid"] != \
        grantee_path["source_legacy_authority_proof_oid"]
    assert "for every distinct over-budget candidate closure" in ledger
    assert "It never coalesces two\n   closures merely because they share one " \
        "provider fid" in ledger
    assert "sealed 519-hop source is representable without weakening the " \
        "64-fact limit" in " ".join(ledger.split())
    assert "sorted_source_provider_sids, sorted_source_action_scopes" in ledger
    assert "checkpoint-coalesces-proof-closures" in ledger


def test_s5_facttree_is_the_authenticated_quarantine_archive():
    """Ordinary facts remain recoverable after shadow and old-root GC."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    assert "FactTree[FactSlot(K(f))] = ADMITTED(fact_record_oid)" in ledger
    assert "S5 FactTree is a\n   grow-only authenticated admission archive" \
        in ledger
    assert "FactTree membership alone can therefore never\n   authorize or " \
        "project a quarantined fact" in ledger
    assert "The first S5 FactTree receives one\n   " \
        "`ADMITTED(fact_record_oid)` row for every `ORDINARY` fact row" \
        in ledger
    assert "both `PUBLISHED` and `RETAINED_QUARANTINE`" in ledger
    assert "Every ordinary durable\n   fact admitted by S5 ordinary " \
        "publication likewise enters the grow-only\n   FactTree once" in ledger
    assert "Removal proposals remain outside that path until\n   atomic action " \
        "admission roots them through `ActionRecord`" in ledger
    assert "`quarantine/` copy is disposable cache only" in ledger
    assert "An `ADMITTED` FactTree hit\nproves immutable admission and " \
        "reachability, not authority by itself" in ledger
    assert "drop-post-s5-quarantined-fact-from-facttree" in ledger
    assert "message is ineligible while shadowed and reappears after restore" \
        in ledger


def test_receipt_proof_digest_has_no_content_hash_cycle():
    """Receipt identity is fixed before its ref enters the ActionRecord."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = exported_beads()
    issue_contracts = "\n".join(
        "\n".join(strings(issue))
        for issue in issues
        if issue["id"].startswith(RECOVERY_EPIC)
    )
    authorization = ledger.index("ActionAuthorization =")
    proof_refs = ledger.index("proof_refs(r) =", authorization)
    proof_digest = ledger.index("proof_digest(r) =", proof_refs)
    admission = ledger.index("admission(a) =", proof_digest)
    receipt_ref = ledger.index(
        'EvidenceRef("receipt", a)',
        admission,
    )
    action_record = ledger.index(
        "ActionRecord[action_record_oid] =",
        receipt_ref,
    )
    assert authorization < proof_refs < proof_digest < admission < \
        receipt_ref < action_record
    assert "hash(canon(the named proof edges, proof_refs(r), " \
        "ActionAuthorization))" in ledger
    assert "proposal/support proof refs plus the\n  service-derived " \
        "`ActionAuthorization` → `proof_digest` → receipt" in ledger
    assert "proposal/support proof refs determine the receipt digest" not in \
        issue_contracts
    assert "proof refs determine proof_digest and signed receipt" not in \
        issue_contracts
    assert "alone determines proof_digest" not in issue_contracts
    assert "The receipt never\nhashes or names its own EvidenceRef" in ledger
    assert "ActionRecord evidence set to equal those exact proof refs plus " \
        "the\none self-matching receipt EvidenceRef" in ledger
    assert re.search(
        r"includes the receipt ref in its own\s+`proof_digest` is rejected "
        r"as a content-hash cycle",
        ledger,
    )


def test_legacy_backfill_reserves_action_slots_without_escalation():
    """Old permissive removals survive without gaining current authority."""
    ledger = (ROOT / "docs" / "TODO.md").read_text()
    issues = {issue["id"]: issue for issue in exported_beads()}
    cutover = "\n".join(strings(issues[f"{RECOVERY_EPIC}.6"]))
    integration = "\n".join(strings(issues[f"{RECOVERY_EPIC}.10"]))

    assert "the victim family's `DIRECT_TARGETS` matrix\n" \
        "   permits that exact removal-family/selector-role pair" in ledger
    assert "membership/chunk/other target that offers a normal selector" \
        in " ".join(ledger.split())
    assert "ActionSlot(MemberPrincipal(public_key))" in ledger
    assert "even when no membership provider exists" in ledger
    assert "LegacyEntryMap[legacy_entry_key]" in ledger
    assert "LegacyUniverseMap[fid]" in ledger
    assert "LegacyUniverseMap[Publisher(publisher_id)]" in ledger
    assert "RETAINED_QUARANTINE(origin_publisher_id)" in ledger
    assert "LegacyMigrationSeal" in ledger
    assert "every legacy slot entry has\n   exactly one `LegacyEntryMap` row" \
        in ledger
    assert '"legacy_universe": <frozen LegacyUniverseMap oid or EMPTY>' \
        in ledger
    assert '"legacy_entries": <frozen LegacyEntryMap oid or EMPTY>' in ledger
    assert '"legacy_iam": <LegacyIamAttestation oid or EMPTY>' in ledger
    assert "quarantine-only victim\n   through its exact " \
        "`LegacyUniverseMap` row" in ledger
    assert "creates the exact `SuppSlot(resolved_sid)` and\n" \
        "   `ActionSlot(Sid(resolved_sid))`" in ledger
    assert "`ActionSlot(Migration(legacy_mask_namespace, victim_fid))` " \
        "before filling\n   them" in ledger
    assert "`LegacyMigrationSeal` binds the `cutover_digest`" in ledger
    assert "`reconciled_s4_root_oid`, `legacy_mask_namespace`" in ledger
    assert "`legacy_effect_census_oid`, `legacy_effect_census_digest`" \
        in ledger
    assert "authenticated inclusion proof for their exact " \
            "`LegacyUniverseMap` row" in " ".join(ledger.split())
    assert "a naked fid, mismatched object" in \
        " ".join(ledger.lower().split())
    assert "illegal legacy direct target" in cutover
    assert "zero-provider principal ActionSlot" in cutover
    assert "inline-target-spec" in integration
