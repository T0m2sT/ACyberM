# ACyberM

CTF / Hack The Box writeups.

## Writeups

| Challenge | Difficulty | Link | Writeup |
|---|---|---|---|
| Cap | Easy | [HTB machine](https://app.hackthebox.com/machines/Cap) | [writeups/HTB-Cap-writeup.md](writeups/HTB-Cap-writeup.md) |
| Nexus | Hard | [HTB machine](https://app.hackthebox.com/machines/Nexus) | [writeups/HTB-Nexus-writeup.md](writeups/HTB-Nexus-writeup.md) |

## Hints

Spoiler-free nudges if you want to try a box yourself before reading the full writeup.

**Cap**
- Three open ports, one is a custom web app. Look there first.
- A download endpoint takes a numeric ID. What happens if you change it?
- Captured traffic can contain more than you'd expect from a cleartext protocol.
- `getcap -r /` is as important as checking for SUID binaries.

**Nexus**
- A plain port scan won't show you everything this app serves. Check vhosts.
- A deleted secret in the latest commit isn't necessarily gone.
- Company "careers" pages can leak more than job openings.
- Debug mode left on in a web framework hands you its version for free.
- Not every automated job is a cron entry, check timers too.
- Git's client tooling validates paths; the object format underneath doesn't have to go through it.
