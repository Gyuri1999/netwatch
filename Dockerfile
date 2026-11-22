# NetWatch in a container — Linux hosts only (needs the host network to see real traffic).
#   docker compose up            → live capture on the host's default interface, agent mode (HTTPS + token on the LAN)
#   docker compose run --rm netwatch --pcap samples/lan-attack.pcap
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump whois iproute2 net-tools openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py index.html edu.js wireshark.js infra.js sectools.js privtools.js protocols.js ciscolab.js uiplus.js pentestui.js socui.js worktools.js opstools.js cmdxlate.js navplus.js anontools.js topomap.js sshui.js vlsm.js updateui.js presenceui.js l2guardui.js assessui.js vulnui.js upnpui.js otui.js acceptui.js sitesui.js labelsui.js calcui.js v6ui.js nacui.js iotinvui.js radioui.js fieldui.js probesui.js acl.js names.js golive.js alertwhy.js i18n.js academy.html manifest.webmanifest sw.js config.example.yaml VERSION update_signers ./
COPY academy ./academy
COPY i18n ./i18n
COPY samples ./samples
COPY rules ./rules
COPY ctf ./ctf
COPY tools ./tools
EXPOSE 8765
ENTRYPOINT ["python", "netwatch.py", "--no-open"]
