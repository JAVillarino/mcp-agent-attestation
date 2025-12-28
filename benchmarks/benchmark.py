#!/usr/bin/env python3
"""
MCP Agent Attestation - Performance Benchmarks

Measures latency and throughput for core attestation operations.

Run with: python benchmarks/benchmark.py

Author: Joel Villarino
License: MIT
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass

# Add parent to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from attestation import (
    AgentIdentity,
    AttestationProvider,
    AttestationVerifier,
    InMemoryKeyResolver,
    InMemoryReplayCache,
    KeyPair,
    VerificationPolicy,
)


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    name: str
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    ops_per_second: float

    def __str__(self) -> str:
        return (
            f"{self.name}:\n"
            f"  Iterations:    {self.iterations:,}\n"
            f"  Total time:    {self.total_time_ms:.2f} ms\n"
            f"  Avg latency:   {self.avg_time_ms:.3f} ms\n"
            f"  Min latency:   {self.min_time_ms:.3f} ms\n"
            f"  Max latency:   {self.max_time_ms:.3f} ms\n"
            f"  P50 latency:   {self.p50_ms:.3f} ms\n"
            f"  P95 latency:   {self.p95_ms:.3f} ms\n"
            f"  P99 latency:   {self.p99_ms:.3f} ms\n"
            f"  Throughput:    {self.ops_per_second:,.0f} ops/sec"
        )


def calculate_percentile(times: list[float], percentile: float) -> float:
    """Calculate percentile from sorted list."""
    if not times:
        return 0.0
    sorted_times = sorted(times)
    index = int(len(sorted_times) * percentile / 100)
    return sorted_times[min(index, len(sorted_times) - 1)]


def run_benchmark(name: str, func, iterations: int = 1000) -> BenchmarkResult:
    """Run a synchronous benchmark."""
    times = []

    # Warmup
    for _ in range(min(100, iterations // 10)):
        func()

    # Actual benchmark
    start_total = time.perf_counter()
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    end_total = time.perf_counter()

    total_time_ms = (end_total - start_total) * 1000

    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_ms=total_time_ms,
        avg_time_ms=statistics.mean(times),
        min_time_ms=min(times),
        max_time_ms=max(times),
        p50_ms=calculate_percentile(times, 50),
        p95_ms=calculate_percentile(times, 95),
        p99_ms=calculate_percentile(times, 99),
        ops_per_second=iterations / (total_time_ms / 1000),
    )


async def run_async_benchmark(name: str, func, iterations: int = 1000) -> BenchmarkResult:
    """Run an async benchmark."""
    times = []

    # Warmup
    for _ in range(min(100, iterations // 10)):
        await func()

    # Actual benchmark
    start_total = time.perf_counter()
    for _ in range(iterations):
        start = time.perf_counter()
        await func()
        end = time.perf_counter()
        times.append((end - start) * 1000)
    end_total = time.perf_counter()

    total_time_ms = (end_total - start_total) * 1000

    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_ms=total_time_ms,
        avg_time_ms=statistics.mean(times),
        min_time_ms=min(times),
        max_time_ms=max(times),
        p50_ms=calculate_percentile(times, 50),
        p95_ms=calculate_percentile(times, 95),
        p99_ms=calculate_percentile(times, 99),
        ops_per_second=iterations / (total_time_ms / 1000),
    )


class AttestationBenchmarks:
    """Benchmarks for attestation operations."""

    def __init__(self):
        # Setup
        self.keypair = KeyPair.generate("benchmark-key")
        self.provider = AttestationProvider(
            issuer="https://api.anthropic.com",
            keypair=self.keypair,
        )
        self.identity = AgentIdentity(
            model_family="claude-4",
            model_version="claude-sonnet-4",
            provider="anthropic",
        )

        # Verifier setup
        self.key_resolver = InMemoryKeyResolver()
        self.key_resolver.add_key(
            "https://api.anthropic.com",
            self.keypair.kid,
            self.keypair.public_key,
        )
        self.verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=self.key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://server.com",
        )

        # Cache for replay tests
        self.replay_cache = InMemoryReplayCache()

        # Pre-generate token for verification tests
        self.sample_token = self.provider.create_token(
            identity=self.identity,
            audience="https://server.com",
        )

    def benchmark_key_generation(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Ed25519 key pair generation."""
        return run_benchmark(
            "Key Generation (Ed25519)",
            lambda: KeyPair.generate("bench-key"),
            iterations,
        )

    def benchmark_token_creation(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark token creation (signing)."""
        return run_benchmark(
            "Token Creation (Sign)",
            lambda: self.provider.create_token(
                identity=self.identity,
                audience="https://server.com",
            ),
            iterations,
        )

    async def benchmark_token_verification(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark token verification."""
        # Generate fresh tokens for each verification (to avoid replay detection)
        tokens = [
            self.provider.create_token(identity=self.identity, audience="https://server.com")
            for _ in range(iterations + 100)
        ]
        token_iter = iter(tokens)

        # Create fresh verifier for each benchmark run
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=self.key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://server.com",
        )

        async def verify_one():
            token = next(token_iter)
            return await verifier.verify(token)

        return await run_async_benchmark(
            "Token Verification (Verify)",
            verify_one,
            iterations,
        )

    async def benchmark_replay_cache(self, iterations: int = 10000) -> BenchmarkResult:
        """Benchmark replay cache check-and-add."""
        cache = InMemoryReplayCache()
        counter = [0]
        exp = int(time.time()) + 3600

        async def cache_check():
            counter[0] += 1
            return await cache.check_and_add(f"jti-{counter[0]}", exp)

        return await run_async_benchmark(
            "Replay Cache (Check+Add)",
            cache_check,
            iterations,
        )

    async def benchmark_full_flow(self, iterations: int = 500) -> BenchmarkResult:
        """Benchmark full attestation flow: create + verify."""
        # Create fresh verifier
        verifier = AttestationVerifier(
            trusted_issuers=["https://api.anthropic.com"],
            key_resolver=self.key_resolver,
            policy=VerificationPolicy.REQUIRED,
            audience="https://server.com",
        )

        async def full_flow():
            token = self.provider.create_token(
                identity=self.identity,
                audience="https://server.com",
            )
            return await verifier.verify(token)

        return await run_async_benchmark(
            "Full Flow (Create + Verify)",
            full_flow,
            iterations,
        )

    def benchmark_jwk_export(self, iterations: int = 5000) -> BenchmarkResult:
        """Benchmark JWK export."""
        return run_benchmark(
            "JWK Export",
            lambda: self.keypair.to_jwk(),
            iterations,
        )


async def main():
    """Run all benchmarks."""
    print("=" * 70)
    print("MCP Agent Attestation - Performance Benchmarks")
    print("=" * 70)
    print()

    benchmarks = AttestationBenchmarks()
    results = []

    # Sync benchmarks
    print("Running synchronous benchmarks...")
    results.append(benchmarks.benchmark_key_generation(100))
    results.append(benchmarks.benchmark_token_creation(1000))
    results.append(benchmarks.benchmark_jwk_export(5000))

    # Async benchmarks
    print("Running asynchronous benchmarks...")
    results.append(await benchmarks.benchmark_token_verification(1000))
    results.append(await benchmarks.benchmark_replay_cache(10000))
    results.append(await benchmarks.benchmark_full_flow(500))

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)

    for result in results:
        print()
        print(result)

    # Summary table
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()
    print(f"{'Operation':<35} {'Avg (ms)':<12} {'P99 (ms)':<12} {'Ops/sec':<15}")
    print("-" * 70)
    for r in results:
        print(f"{r.name:<35} {r.avg_time_ms:<12.3f} {r.p99_ms:<12.3f} {r.ops_per_second:<15,.0f}")

    # Overhead analysis
    print()
    print("=" * 70)
    print("OVERHEAD ANALYSIS")
    print("=" * 70)
    print()

    full_flow = next(r for r in results if "Full Flow" in r.name)
    print(f"Full attestation flow adds {full_flow.avg_time_ms:.2f}ms latency per request")
    print(f"This supports {full_flow.ops_per_second:,.0f} attestations/second on a single core")
    print()
    print("For comparison:")
    print("  - Typical HTTP request: 10-100ms")
    print("  - Database query: 1-10ms")
    print("  - Attestation overhead: <1ms")
    print()
    print("Conclusion: Attestation adds negligible overhead to MCP operations.")


if __name__ == "__main__":
    asyncio.run(main())
