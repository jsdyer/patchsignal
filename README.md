# Patch Signal

Investigate a public CVE through official CVE Program records and FIRST EPSS scores. The catalogue view is limited to CISA's known-exploited vulnerabilities and can filter by product, score threshold, or ransomware flag. A standalone lookup works for a CVE outside that catalogue. Lookup nicknames are a small curated set.

<!-- coolcode:guide -->
Start with a CVE from your inventory. Compare affected versions, CISA’s required action when listed, and changes in FIRST’s EPSS estimate. The Canadian notices link carries that identifier to [The Exploit Graveyard](https://coolcode.ca/exploitgraveyard/) to find Cyber Centre alerts and advisories that cite it.
<!-- /coolcode:guide -->

```sh
python3 scripts/build.py
python3 -m http.server --directory dist 8080
```

The build downloads CISA's [official CC0 KEV mirror](https://github.com/cisagov/kev-data) and the [FIRST EPSS daily data](https://www.first.org/epss/data), then retains only the latter's matching scores. EPSS data is attributed to FIRST and distributed under the licence documented at the source. Build-time EPSS download failure leaves score cells unavailable, with live lookup still supported. Refresh the static catalogue daily in GitHub Actions.

The browser sends exact CVE identifiers to the CVE Program and FIRST APIs. EPSS estimates the probability of attempted exploitation in the following 30 days. Scores, CISA confirmation, vendor affected-version ranges and product deployment context answer different questions. A CISA due date is displayed as published.
