"""Offline checks for provider orchestration and coverage semantics."""

from discovery import Candidate, DiscoveryEngine, DiscoveryProvider, ProviderResult


class FakeProvider(DiscoveryProvider):
    def __init__(self, name, result=None, error=None, enabled=True):
        self.name = name
        self.result = result
        self.error = error
        self.enabled = enabled
        self.calls = 0

    def search(self, brand_profile, query_plan, progress):
        self.calls += 1
        if self.error:
            raise self.error
        return ProviderResult.success(self.name, self.result or [])


def main():
    shared = Candidate(url="https://same.example", source="one",
                       source_kind="test")
    first = FakeProvider("first", [shared])
    second = FakeProvider("second", [Candidate(
        url="https://same.example", source="two", source_kind="test")])
    failed = FakeProvider("failed", error=RuntimeError("offline"))
    disabled = FakeProvider("disabled", enabled=False)

    run = DiscoveryEngine([first, second, failed, disabled]).run({}, [])
    assert first.calls == second.calls == failed.calls == 1
    assert disabled.calls == 0
    assert len(run.candidates) == 1
    assert run.provider_results["first"].searched
    assert run.provider_results["first"].result_count == 1
    assert run.provider_results["failed"].failed
    assert not run.provider_results["failed"].searched
    assert run.provider_results["disabled"].skipped

    empty = DiscoveryEngine([FakeProvider("clean")]).run({}, [])
    assert empty.provider_results["clean"].searched
    assert empty.provider_results["clean"].result_count == 0
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
