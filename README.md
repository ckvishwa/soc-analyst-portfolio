# LinkedIn Job Scraper — Free & Local

No API key. No Apify account. No cost.

---

## Setup

```bash
# 1. Install Node.js (v18+) if you haven't
# https://nodejs.org

# 2. Install dependencies
npm install

# 3. Run
node scrape.js
```

---

## Usage

### Defaults (SOC Analyst, United States, 30 jobs)
```bash
node scrape.js
```

### Custom keyword + location
```bash
node scrape.js --keyword "Detection Engineer" --location "New York"
```

### Remote only
```bash
node scrape.js --keyword "Cybersecurity Analyst" --location "United States" --remote
```

### Entry level only
```bash
node scrape.js --keyword "SOC Analyst" --location "Connecticut" --entry
```

### Grab more results
```bash
node scrape.js --keyword "Malware Analyst" --location "Remote" --limit 100
```

### Custom output file
```bash
node scrape.js --keyword "Incident Response" --output "ir_jobs.csv"
```

### Full combo
```bash
node scrape.js --keyword "SOC Analyst" --location "United States" --remote --entry --limit 50 --output "soc_jobs.csv"
```

---

## Output

CSV file with columns:
- Title, Company, Location, Date
- Link (job page), ApplyLink
- Seniority, Function, Type, Industries
- Description (first 500 chars)

---

## Filters you can edit in `scrape.js`

| Filter | Options |
|--------|---------|
| `time` | `WEEK`, `MONTH`, `ANY` |
| `type` | `FULL_TIME`, `PART_TIME`, `CONTRACT`, `INTERNSHIP` |
| `experience` | `INTERNSHIP`, `ENTRY_LEVEL`, `ASSOCIATE`, `MID_SENIOR`, `DIRECTOR` |
| `onSiteOrRemote` | `ON_SITE`, `REMOTE`, `HYBRID` |

---

## Troubleshooting

**"No jobs collected"**
→ LinkedIn may have blocked the session. Wait 10 min and retry.
→ Try `--limit 10` first to test.

**Puppeteer / Chrome errors on Linux**
→ Run: `sudo apt-get install -y chromium-browser`
→ Or set env: `PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser node scrape.js`

**Rate limited**
→ Don't run back-to-back. Space runs by 5+ minutes.
→ Reduce `--limit` if getting blocked fast.

---

## Anti-Detection Notes

- Runs headless (invisible browser)
- `slowMo: 200` adds human-like delays
- Skips images/fonts to look lighter
- Don't run 500+ jobs in one go — LinkedIn will soft-ban your IP

---

## Villain Move
Point this at 3–5 target companies, pipe CSV into a Google Sheet,
and cold-email the hiring manager before the job is 7 days old.
Most applicants wait. You don't.
