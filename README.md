# Digital Election System (Final Fixed)

Features:
- User registration & login with password hashing
- Two-step login with OTP (OTP printed in console for demo)
- Single configurable election with name and date range
- Candidates with party information
- One-vote-per-user enforcement
- User dashboard with election info and vote status
- Admin dashboard with stats, election configuration (with calendar date pickers), and candidate management
- Results page with table + Chart.js charts (candidate votes + party vote share)
- Export results as CSV
- JSON API for results
- Custom 404 and 500 error pages

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the app:

```bash
python app.py
```

Or on Windows, double-click `run.bat`.

3. Open in browser:

```
http://127.0.0.1:5000
```

Default admin login:
- username: `admin`
- password: `admin123`
