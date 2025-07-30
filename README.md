# ICMP Spoof Responder with ARP Poisoning (Scapy)

> A simple Python script that responds to ICMP echo requests (pings) using spoofed IPs, based on ARP poisoning logic.  
> Built for educational purposes and experimentation in controlled environments only.

---

## What is this?

This tool simulates a basic **network spoofing attack** using [Scapy](https://scapy.net/). It:

1. Listens for ARP requests on the network
2. Responds with a fake ARP reply, associating a target IP with the attacker's MAC
3. Sniffs for incoming ICMP Echo Requests (ping)
4. Sends a spoofed ICMP Echo Reply pretending to be that IP

This mimics how some basic **man-in-the-middle** or **host impersonation** attacks work.

---

## How it works

1. A victim sends an ARP request: “Who has 10.9.0.9?”
2. This script replies: “I (attacker) have 10.9.0.9 — here’s my MAC.”
3. The victim stores that in its ARP cache.
4. When the victim pings `10.9.0.9`, the ICMP Echo Request comes to you.
5. The script sends a forged ICMP Echo Reply using `src=10.9.0.9`.

Normal Behavior:


<img src="https://github.com/focarica/ICMP-Spoof/blob/main/img/ping-9-spoofing.png?raw=true">

and with the script running, 


<img src="https://github.com/focarica/ICMP-Spoof/blob/main/img/ping-9-wspoofing.png?raw=true">

---

## Requirements

- Python 3.8+
- `scapy` installed:
- Root privileges (to send low-level packets)

---

## How to run

Edit the script and set the correct interface:

`INTERFACE = "xxxxxx"`

Then run with:

```bash
sudo python3 spoof_icmp.py
```

From another host on the same network, try:

```bash
ping <spoofed-ip>
```

You should see the victim receiving ICMP replies from a fake IP (yours).

---

## Legal Disclaimer

> This project is for **educational and testing purposes only** in **home labs** or **authorized environments**.  
> Do **not** use it on networks you don't have explicit permission to test.  
> Misuse may be illegal and unethical.
