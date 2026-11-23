# Patch Signal

Investigate a public CVE through official CVE Program records and FIRST EPSS scores. The catalogue view is limited to CISA's known-exploited vulnerabilities and can filter by product, score threshold, or ransomware flag. A standalone lookup works for a CVE outside that catalogue. Lookup nicknames are a small curated set.

<!-- coolcode:guide -->
Paste CVE identifiers from your inventory or a bulletin to match up to 250 distinct IDs against the saved CISA known-exploited catalogue. Open an identifier for affected-version records, patch guidance and FIRST EPSS estimates. Not listed in KEV does not mean safe, and an ID match does not establish that your installed version is affected.
<!-- /coolcode:guide -->

[Search Canadian notices in The Exploit Graveyard](https://coolcode.ca/exploitgraveyard/).

```sh
python3 scripts/build.py
python3 -m http.server --directory dist 8080
```

The build downloads CISA's [official CC0 KEV mirror](https://github.com/cisagov/kev-data) and the [FIRST EPSS daily data](https://www.first.org/epss/data), then retains only the latter's matching scores. EPSS data is attributed to FIRST and distributed under the licence documented at the source. Build-time EPSS download failure leaves score cells unavailable, with live lookup still supported. Refresh the static catalogue daily in GitHub Actions.

The browser sends exact CVE identifiers to the CVE Program and FIRST APIs. EPSS estimates the probability of attempted exploitation in the following 30 days. Scores, CISA confirmation, vendor affected-version ranges and product deployment context answer different questions. A CISA due date is displayed as published.


## Added browser workflow

Paste CVE identifiers from your inventory or a bulletin to match up to 250 distinct IDs against the saved CISA known-exploited catalogue. Open an identifier for affected-version records, patch guidance and FIRST EPSS estimates. Not listed in KEV does not mean safe, and an ID match does not establish that your installed version is affected.
