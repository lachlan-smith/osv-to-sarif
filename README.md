# osv-to-sarif

Run govulncheck with `govulncheck --json ./... | jq --slurp 'map(select(.vulnerability) | .vulnerability)' > osv.json`