# Live-capture image: the bscaf runtime plus auditd, for a privileged container
# that records real system calls from the host kernel (see scripts/live_capture.sh).
FROM bscaf
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends auditd procps curl \
    && rm -rf /var/lib/apt/lists/*
