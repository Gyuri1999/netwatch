# NetWatch in a container — Linux hosts only (needs the host network to see real traffic).
#   docker compose up            → live capture on the host's default interface
#   docker compose run --rm netwatch --pcap samples/lan-attack.pcap
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump whois iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY netwatch.py pentest.py index.html edu.js config.example.yaml ./
COPY samples ./samples
COPY tools ./tools
EXPOSE 8765
ENTRYPOINT ["python", "netwatch.py", "--no-open"]
