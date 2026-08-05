import pytest

from peerlog.cloud import CloudMetrics

from bench.cloud_contention import _cleanup_live_r2, provider_request_report


class Provider:
    def __init__(self, **values):
        self.metrics = CloudMetrics(**values)


def test_contention_report_counts_and_prices_logical_adapter_operations():
    first = Provider(gets=7, puts=5, cas=3, lists=2)
    report = provider_request_report((
        first,
        first,
        Provider(
            gets=4,
            puts=1,
            cas=2,
            multipart_creates=1,
            part_copies=1,
            multipart_completes=1,
        ),
    ))

    assert report["logical_operations"] == {
        "gets": 11,
        "puts": 6,
        "cas": 5,
        "lists": 2,
        "multipart_creates": 1,
        "part_copies": 1,
        "multipart_completes": 1,
    }
    assert report["logical_class_a"] == 16
    assert report["logical_class_b"] == 11
    assert report["projected_logical_r2_usd"] == 0.00007596


def test_live_cleanup_is_hard_scoped_to_one_generated_contention_prefix():
    prefix = "poc16-contention/run-" + "a" * 32

    class MutationClient:
        def __init__(self, store):
            self.store = store

        def delete_object(self, **request):
            physical = request["Key"]
            assert physical.startswith(prefix + "/")
            self.store.keys.remove(physical[len(prefix) + 1:])

    class Store:
        def __init__(self):
            self.keys = ["cloud/a", "cloud/b"]
            self._mutation_client = MutationClient(self)

        def list(self, _prefix):
            return tuple(self.keys)

        @staticmethod
        def _read_args(key):
            return {"Bucket": "isolated", "Key": prefix + "/" + key}

    provider = Provider()
    provider.store = Store()
    assert _cleanup_live_r2((provider,), prefix) == {
        "deleted": 2, "remaining": 0}

    with pytest.raises(ValueError, match="outside"):
        _cleanup_live_r2((provider,), "tinyp2p")
