# pcaplab

A high-performance, streaming PCAP perturbation toolkit implementing Threat Model I/II:
- Packet loss, retransmission, TCP sequence offset
- Packet length forgery, (offline) packet rate modification placeholder
- Streaming chunked processing for large PCAPs
- Directory batch runner, mirroring date/pcap layout, skipping `encrypted_pcaps`

## Install
```bash
pip install -e .
