# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Tools download stage ──────────────────────────────────────────────────────
FROM python:3.12-slim AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates perl p7zip-full && \
    rm -rf /var/lib/apt/lists/*

# Gobuster
RUN curl -fsSL "https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz" -o /tmp/gobuster.tar.gz && \
    tar xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster && \
    rm /tmp/gobuster.tar.gz

# Hashcat
RUN curl -fsSL "https://github.com/hashcat/hashcat/releases/download/v7.1.2/hashcat-7.1.2.7z" -o /tmp/hashcat.7z && \
    7z x /tmp/hashcat.7z -o/opt/hashcat -y > /dev/null && \
    rm /tmp/hashcat.7z

# Nikto  
RUN curl -fsSL "https://github.com/sullo/nikto/archive/refs/heads/master.tar.gz" -o /tmp/nikto.tar.gz && \
    mkdir -p /opt/nikto && \
    tar xzf /tmp/nikto.tar.gz -C /opt/nikto --strip-components=1 && \
    rm /tmp/nikto.tar.gz

# Rockyou wordlist (~50MB compressed, 140MB raw)
RUN curl -fsSL "https://github.com/zacheller/rockyou/raw/master/rockyou.txt.tar.gz" -o /tmp/rockyou.txt.tar.gz && \
    tar xzf /tmp/rockyou.txt.tar.gz -C /tmp/ && \
    mv /tmp/rockyou.txt /opt/rockyou.txt && \
    rm /tmp/rockyou.txt.tar.gz

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl sqlmap nmap dirb p7zip-full dnsutils perl \
    libjson-perl libxml-writer-perl \
    aircrack-ng tshark wifite && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=tools /usr/local/bin/gobuster /usr/local/bin/gobuster
COPY --from=tools /opt/hashcat /opt/hashcat
COPY --from=tools /opt/nikto /opt/nikto
COPY --from=tools /opt/rockyou.txt /usr/share/wordlists/rockyou.txt

RUN ln -sf /opt/hashcat/hashcat-7.1.2/hashcat.bin /usr/local/bin/hashcat && \
    chmod -R a+rw /opt/hashcat/hashcat-7.1.2 && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    mkdir -p /usr/share/wordlists /usr/share/dirb

RUN useradd -m -u 1000 appuser && \
    chown -R appuser /app && \
    mkdir -p /tunnel && chown appuser:appuser /tunnel
USER appuser

COPY --chown=appuser . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
