
# Digital Election System (Final Fixed)

A secure web-based election system built with Python (Flask) featuring OTP-based login, configurable elections, candidate management, blockchain-style audit trail, and visual analytics.

---

## ✅ Features

- User registration & login with **password hashing**
- Two-step login with **OTP verification**  
  *(OTP printed in console for demo)*
- Single configurable election with **name and date range**
- Candidate management with **party information**
- **One-vote-per-user** enforcement at backend
- User dashboard showing:
  - Election details (name, schedule, status)
  - Whether the user has already voted
- Admin dashboard with:
  - Stats (total users, total votes, turnout)
  - Election configuration (with calendar date picker)
  - Candidate add / view / delete
- Results page with:
  - Table view
  - **Chart.js** charts:
    - Candidate votes bar chart  
    - Party vote share chart
- Export results as **CSV**
- JSON **API endpoint** for results
- Custom **404** and **500** error pages

---

## 🛠 Setup Instructions

### 1️⃣ Install dependencies

```bash
pip install -r requirements.txt

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

## License

This project is proprietary and closed-source.  
No part of this codebase may be copied, modified, or distributed without permission.
© 2025 Shubham Chakraborty. All Rights Reserved.

