from python:3.10-bullseye

copy . /opt/scapy
workdir /opt/scapy
entrypoint bash
# entrypoint python3 /opt/scapy/run.py
