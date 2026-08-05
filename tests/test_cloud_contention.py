from peerlog.cloud import CloudMetrics

from bench.cloud_contention import provider_request_report


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
