#!/bin/sh
# Deploys worker.js + page.html to Cloudflare (worker "calendar", D1 binding DB, KEY var),
# to Cloudflare Pages (daybook-office), and pushes the public files to GitHub
# (repo mosheder50/daybook-calendar (owner's account since 2026-11-26; was amy-brooks-fa), GitHub Pages https://mosheder50.github.io/daybook-calendar/?k=<KEY>).
T=$(grep -o 'cfut_[A-Za-z0-9_-]*' ~/notes/accounts/cloudflare.md); A=8bcd93500375c6b4d6b955453b34953e
KEY=$(cat "$(dirname "$0")/key.txt")
# 2026-11-24 sign-in: auth.env (private, never pushed) holds AUTH_USER, AUTH_SALT, AUTH_HASH=sha256(salt+password), AUTH_SECRET (token signing).
. "$(dirname "$0")/auth.env"; [ -n "$AUTH_USER" ] && [ -n "$AUTH_HASH" ] && [ -n "$AUTH_SECRET" ] || { echo "auth.env missing - stop"; exit 1; }
# 2026-11-24 (3) forgot-password by text: relay.env (private, chmod 600, never pushed) holds RELAY_SECRET (the relay computer's key for
# /api/reset-outbox) and RESET_PHONE (+1..., the phone the code is texted to; EMPTY = feature off, link hidden).
RELAY_SECRET=; RESET_PHONE=; . "$(dirname "$0")/relay.env"; [ -n "$RELAY_SECRET" ] || { echo "relay.env missing - stop"; exit 1; }
RBIND=',{"type":"secret_text","name":"RELAY_SECRET","text":"'$RELAY_SECRET'"}'; [ -n "$RESET_PHONE" ] && RBIND=$RBIND',{"type":"secret_text","name":"RESET_PHONE","text":"'$RESET_PHONE'"}'
RPG=',"RELAY_SECRET":"'$RELAY_SECRET'"'; [ -n "$RESET_PHONE" ] && RPG=$RPG',"RESET_PHONE":"'$RESET_PHONE'"'
RDIG=$(echo "$RESET_PHONE" | tr -dc 0-9 | tail -c 10); [ -n "$RDIG" ] || RDIG=__nophone__
# token gen = current "gen" row of that app's D1 table auth_settings (set when the password is changed from the page), else 0
gen() { curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$A/d1/database/$1/query" -H "Authorization: Bearer $T" -H 'content-type: application/json' -d '{"sql":"SELECT v FROM auth_settings WHERE k='"'gen'"'"}' | python3 -c 'import json,sys
try: r=json.load(sys.stdin)["result"][0]["results"]; print(r[0]["v"] if r else "0")
except Exception: print("0")'; }
mint() { python3 -c 'import sys,hmac,hashlib,base64,time;u,s,g=sys.argv[1:4];p=u+"."+str(int(time.time()*1000)+600000)+"."+g;print(p+"."+base64.urlsafe_b64encode(hmac.new(s.encode(),p.encode(),hashlib.sha256).digest()).decode().rstrip("="))' "$1" "$2" "$3"; }
META='{"main_module":"worker.js","compatibility_date":"2025-06-01","bindings":[{"type":"d1","name":"DB","id":"b0e84bb7-47ac-46ec-8d67-a3d607cb1949"},{"type":"plain_text","name":"KEY","text":"'$KEY'"},{"type":"secret_text","name":"AUTH_USER","text":"'$AUTH_USER'"},{"type":"secret_text","name":"AUTH_SALT","text":"'$AUTH_SALT'"},{"type":"secret_text","name":"AUTH_HASH","text":"'$AUTH_HASH'"},{"type":"secret_text","name":"AUTH_SECRET","text":"'$AUTH_SECRET'"}'$RBIND']}'
cd "$(dirname "$0")"
curl -s -X PUT "https://api.cloudflare.com/client/v4/accounts/$A/workers/scripts/calendar" -H "Authorization: Bearer $T" \
  -F "metadata=$META;type=application/json" \
  -F "worker.js=@worker.js;type=application/javascript+module" \
  -F "page.html=@page.html;type=text/plain" | python3 -c "import json,sys;d=json.load(sys.stdin);print('success',d['success'],d.get('errors'))"
curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$A/workers/scripts/calendar/subdomain" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{"enabled":true,"previews_enabled":false}' | python3 -c "import json,sys;d=json.load(sys.stdin);print('subdomain',d['success'],d.get('errors'))"
# Round 5: same app on Cloudflare Pages (daybook-office.pages.dev) - _worker.js with page.html inlined, same D1 + KEY (pages/wrangler.toml)
python3 - <<'PY'
import json,os
d=os.path.dirname(os.path.abspath("worker.js"))+"/"
w=open(d+"worker.js").read().replace('import PAGE from "./page.html";','const PAGE = '+json.dumps(open(d+"page.html").read())+';')
open(d+"pages/public/_worker.js","w").write(w)
PY
(cd pages && printf '{"AUTH_USER":"%s","AUTH_SALT":"%s","AUTH_HASH":"%s","AUTH_SECRET":"%s"%s}' "$AUTH_USER" "$AUTH_SALT" "$AUTH_HASH" "$AUTH_SECRET" "$RPG" > /tmp/pgsec.json && CLOUDFLARE_API_TOKEN=$T CLOUDFLARE_ACCOUNT_ID=$A npx -y wrangler@latest pages secret bulk /tmp/pgsec.json --project-name daybook-office 2>&1 | grep -E "Finished|uccess|rror"; rm -f /tmp/pgsec.json)
(cd pages && printf '{"AUTH_USER":"%s","AUTH_SALT":"%s","AUTH_HASH":"%s","AUTH_SECRET":"%s"%s}' "$AUTH_USER" "$AUTH_SALT" "$AUTH_HASH" "$AUTH_SECRET" "$RPG" > /tmp/pgsec.json && CLOUDFLARE_API_TOKEN=$T CLOUDFLARE_ACCOUNT_ID=$A npx -y wrangler@latest pages secret bulk /tmp/pgsec.json --project-name sarah-calendar 2>&1 | grep -E "Finished|uccess|rror"; rm -f /tmp/pgsec.json)
(cd pages && CLOUDFLARE_API_TOKEN=$T CLOUDFLARE_ACCOUNT_ID=$A npx -y wrangler@latest pages deploy --branch main 2>&1 | grep -E "Success|complete|ERROR")
# 2026-11-24: same app + same data also at sarah-calendar.pages.dev (owner wanted "sarah" in the link)
(cd pages && CLOUDFLARE_API_TOKEN=$T CLOUDFLARE_ACCOUNT_ID=$A npx -y wrangler@latest pages deploy --project-name sarah-calendar --branch main 2>&1 | grep -E "Success|complete|ERROR")

# GitHub (2026-11-22): copy ONLY the public files into the repo folder, refuse to push if the access key,
# a Cloudflare/GitHub token or any client name is in them, then commit and push. GitHub Pages rebuilds in ~1 minute.
R=$HOME/agent/results/daybook-calendar-repo
GT=$(grep -o 'ghp_[A-Za-z0-9]*' ~/notes/accounts/github-owner.md | tail -1)   # mosheder50 token (was Amy's, accounts/github.md)
[ -d "$R/.git" ] || { git clone -q "https://x-access-token:$GT@github.com/mosheder50/daybook-calendar.git" "$R" 2>&1 | grep -v "empty repository"; git -C "$R" remote set-url origin https://github.com/mosheder50/daybook-calendar.git; }
git -C "$R" config user.name "Amy Brooks"; git -C "$R" config user.email "amy.brooks@fromassistant.com"
cp page.html "$R/index.html"; cp page.html worker.js deploy.sh gen-holidays.mjs README.md "$R/"; touch "$R/.nojekyll"
curl -s -H "Authorization: Bearer $(mint "$AUTH_USER" "$AUTH_SECRET" "$(gen b0e84bb7-47ac-46ec-8d67-a3d607cb1949)")" "https://calendar.daybook-amy.workers.dev/c/$KEY/api/clients" | python3 -c '
import json,sys,re
cl=json.load(sys.stdin)["clients"]; out=set()
for c in cl:
  out.add(c["name"])
  if c.get("medicaid") and len(c["medicaid"]) >= 4: out.add(c["medicaid"])   # Medicaid numbers never go to GitHub either
  for w in re.findall(r"[A-Za-z]{4,}", c["name"]):
    if w.lower() not in ("esther",): out.add(w)   # Esther = also the holiday name Taanis Esther in the page
print("\n".join(sorted(out)))' > /tmp/gh-names.txt
[ -s /tmp/gh-names.txt ] || { echo "GITHUB: could not read the client list for the name check - NOT pushed"; exit 1; }
BAD=$(cd "$R" && { grep -rIl --exclude-dir=.git -F "$KEY" .; grep -rIlE --exclude-dir=.git 'cfut_[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}' .; grep -rIlw --exclude-dir=.git -F -f /tmp/gh-names.txt .; grep -rIl --exclude-dir=.git -F -e "$AUTH_SALT" -e "$AUTH_HASH" -e "$AUTH_SECRET" -e "$RELAY_SECRET" -e "$RDIG" .; OU=$(cat "$HOME"/agent/results/*/auth.env | sed -n 's/^AUTH_USER=//p' | grep -vx "$AUTH_USER"); [ -n "$OU" ] && echo "$OU" | grep -rIli --exclude-dir=.git -F -f - .; ls -a | grep -E '^backup|^bak-|key\.txt|wrangler\.toml|auth\.env|relay\.env'; } | sort -u)
[ -z "$BAD" ] || { echo "GITHUB: key/token/client name/private file found in: $BAD - NOT pushed"; exit 1; }
cd "$R" && git add -A && { git diff --cached --quiet && echo "GITHUB: no changes"; } || { git commit -q -m "Update $(date '+%Y-%m-%d %H:%M %Z')" && git push -q "https://x-access-token:$GT@github.com/mosheder50/daybook-calendar.git" HEAD:main 2>&1 | sed "s/$GT/***/g"; echo "GITHUB: pushed $(git rev-parse --short HEAD)"; }
# 2026-11-24: same files also to repo mosheder50/sarah (https://mosheder50.github.io/sarah/?k=<KEY>)
git -C "$R" push -q "https://x-access-token:$GT@github.com/mosheder50/sarah.git" HEAD:main 2>&1 | sed "s/$GT/***/g"; echo "GITHUB sarah: pushed $(git -C "$R" rev-parse --short HEAD)"
