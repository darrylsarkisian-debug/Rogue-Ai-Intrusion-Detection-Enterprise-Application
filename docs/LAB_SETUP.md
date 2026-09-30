# Week 1: Build the lab

Goal by end of week: repo on GitHub, demo runs, sensor VM sees traffic from two Windows VMs,
and you can export the first real log samples for the loaders.

## Lab layout (about 16 GB RAM free is comfortable)

| VM | OS | RAM | Role |
|---|---|---|---|
| sensor | Ubuntu Server 22.04 or 24.04 | 6-8 GB | Zeek + Wazuh manager + detectors |
| client1 | Windows 10/11 | 4 GB | "Employee" PC: browses, pastes into ChatGPT, later runs Ollama |
| client2 | Windows 10/11 | 4 GB | Second user; approved-software baseline |
| attacker (optional, week 4) | Kali or Ubuntu | 2 GB | Controlled spray/scan against YOUR lab only |

Hypervisor: Hyper-V (built into Windows Pro) or VirtualBox. Put all VMs on one internal
virtual switch, and give the sensor a second NIC that mirrors traffic.

## Getting the sensor to see traffic

- **Hyper-V:** on each client VM's network adapter, Advanced Features > Port mirroring = Source.
  On the sensor's mirror NIC, set Port mirroring = Destination. Then the sensor NIC sees client traffic.
- **VirtualBox:** put all VMs on the same "Internal Network"; on the sensor NIC set Promiscuous Mode = Allow All.
- Simplest alternative to start: make the sensor the clients' default gateway/DNS (NAT + forwarding),
  so all client traffic passes through it. Less realistic, but works in an hour.

## Install order

1. **Ubuntu sensor:** install, update, set a static IP on the lab network.
2. **Zeek:** install from the official Zeek package repo (see docs.zeek.org, "Installing Zeek").
   Set `interface=` in `node.cfg` to the mirror NIC, then `zeekctl deploy`. Logs land in the Zeek `logs/current/` folder
   (`dns.log`, `conn.log`, `ssl.log`, `http.log`). Ask Zeek for JSON logs by loading `policy/tuning/json-logs`.
3. **Wazuh:** use the official all-in-one installer from documentation.wazuh.com (quickstart). Check the current
   version and command on that page rather than copying old ones. Then install the Wazuh agent on client1 and client2.
4. **Detectors:** clone the repo on the sensor, `pip install -r requirements.txt`, run `python run_demo.py --no-cloud`.

## Traffic to generate on client1 (this is your test data)

- Browse normally for 10 minutes (Outlook web, GitHub, Google).
- Visit chatgpt.com, claude.ai, and chat.deepseek.com. Paste a few paragraphs of made-up text into each.
- Upload a fake document (a dummy .docx of made-up text) to one of them.
- Later: install Ollama and a small MCP server for Goal 3; use a lab-only tool for Goal 2 in week 4.

Use invented content only. Do not paste real client or personal data into the lab.

## What to export and send back (sanitize first)

1. Zeek `dns.log` and `conn.log` (about 200 lines each is plenty). If you have `ssl.log`, include ~200 lines.
2. Wazuh: a few Windows events including at least one failed logon (Event ID 4625), from
   `/var/ossec/logs/alerts/alerts.json`.
3. Replace real names/IPs you care about privacy-wise with placeholders, or send as-is if it's only your lab.

With those I will write `loaders/zeek_loader.py` and `loaders/wazuh_loader.py` that convert them into the
proxy/auth/flow/inventory columns the detectors already use.

## Note on Goal 1 in Zeek

Encrypted traffic hides content, but Zeek still gives you the destination name (DNS query and TLS server name)
and bytes sent (`orig_bytes` in conn.log). That is enough for the size-based rules. It cannot tell a paste from
an attachment, so findings stay "inferred from size".
