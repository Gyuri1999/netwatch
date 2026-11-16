#!/bin/bash
# NetWatch launcher
#   ./run.sh                          live capture (asks for sudo password)
#   ./run.sh --demo                   simulated traffic & attacks
#   ./run.sh --pcap samples/lan-attack.pcap   replay a capture file
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  echo "Installing dependencies into .venv …"
  python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt || exit 1
fi
if [[ " $* " == *" --demo "* || " $* " == *" --pcap "* ]]; then
  exec .venv/bin/python netwatch.py "$@"
else
  exec sudo .venv/bin/python netwatch.py "$@"
fi
