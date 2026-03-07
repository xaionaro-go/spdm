# Multi-stage Dockerfile for running spdm reference interop tests
# against the DMTF spdm-emu (libspdm) reference implementation.
FROM ubuntu:24.04 AS spdm-emu-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake gcc g++ make libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --recursive --depth=1 https://github.com/DMTF/spdm-emu.git

RUN --mount=type=cache,target=/root/.ccache \
    apt-get update && apt-get install -y --no-install-recommends ccache && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p spdm-emu/build && cd spdm-emu/build && \
    cmake \
        -DARCH=x64 \
        -DTOOLCHAIN=GCC \
        -DTARGET=Release \
        -DCRYPTO=openssl \
        -DCMAKE_C_COMPILER_LAUNCHER=ccache \
        .. && \
    make copy_sample_key && \
    make -j"$(nproc)"

FROM golang:1.24-bookworm AS test-runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=spdm-emu-builder /build/spdm-emu/build/bin /opt/spdm-emu/bin

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

CMD ["sh", "-c", "\
    COVERPKGS=$( \
        go list ./pkg/... \
        | grep -v '/gen/' \
        | grep -v 'crypto/stdlib' \
        | paste -sd, - \
    ) \
    && go test ./tests/reference/interop/ \
        -v \
        -count=1 \
        -timeout=300s \
        -coverprofile=/tmp/reference-coverage.out \
        -coverpkg=$COVERPKGS \
        -tags=reference \
        -args \
            -spdm-emu-bin=/opt/spdm-emu/bin \
            -spdm-port=2323 \
    ; exitcode=$? \
    ; echo '=== Reference Interop Coverage ===' \
    ; go tool cover -func=/tmp/reference-coverage.out 2>/dev/null | tail -1 \
    ; echo '=== Per-Package Coverage ===' \
    ; go tool cover -func=/tmp/reference-coverage.out 2>/dev/null \
        | grep -v '^total:' \
        | awk '{pkg=$1; sub(/:[^:]+$/, \"\", pkg); pct=$3+0; cov[pkg]+=pct; n[pkg]++} END{for(p in cov) printf \"%-60s %6.1f%% (%d funcs)\\n\", p, cov[p]/n[p], n[p]}' \
        | sort \
    ; exit $exitcode \
"]
