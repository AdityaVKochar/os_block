# Live-capture image: the bscaf runtime plus bpftrace (eBPF) and auditd, for a
# privileged container that records real system calls from the host kernel.
# Build: docker build -t bscaf-live -f deploy/live/Dockerfile deploy/live
# Run:   docker run --rm --privileged --pid=host -v "$PWD":/app -w /app bscaf-live python scripts/live_capture.py
FROM bscaf
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends bpftrace auditd procps curl \
    && rm -rf /var/lib/apt/lists/*
