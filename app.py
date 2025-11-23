from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps
from datetime import datetime, date, timedelta
import random
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"

DB_NAME = "voting.db"


# ----------------- DB HELPERS -----------------

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and insert default data if DB doesn't exist."""
    if os.path.exists(DB_NAME):
        return

    conn = get_db_connection()
    cur = conn.cursor()

    # Users table (with OTP fields)
    cur.execute(
        """CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TEXT,
                last_login TEXT,
                otp_code TEXT,
                otp_expires_at TEXT
            );"""
    )

    # Single election table
    cur.execute(
        """CREATE TABLE election (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL,
                start_date TEXT,
                end_date TEXT
            );"""
    )

    # Candidates table
    cur.execute(
        """CREATE TABLE candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                party TEXT
            );"""
    )

    # Votes table
    cur.execute(
        """CREATE TABLE votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                candidate_id INTEGER NOT NULL,
                created_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(candidate_id) REFERENCES candidates(id)
            );"""
    )

    # Blockchain-style blocks table for vote audit
    cur.execute(
        """CREATE TABLE blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                index_no INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                vote_id INTEGER NOT NULL,
                previous_hash TEXT,
                hash TEXT NOT NULL,
                FOREIGN KEY(vote_id) REFERENCES votes(id)
            );"""
    )


    # Insert default election with dates around today
    today = date.today()
    start = (today - timedelta(days=1)).isoformat()
    end = (today + timedelta(days=7)).isoformat()

    cur.execute(
        "INSERT INTO election (id, name, start_date, end_date) VALUES (1, ?, ?, ?);",
        ("General Election", start, end),
    )

    # Insert some default candidates
    candidates = [
        ("Alice Sharma", "Progressive Party"),
        ("Bharat Singh", "National Front"),
        ("Cyrus Mehta", "Liberal Union"),
    ]
    cur.executemany(
        "INSERT INTO candidates (name, party) VALUES (?, ?);",
        candidates,
    )

    # Create admin user
    admin_username = "admin"
    admin_password = "admin123"
    admin_hash = generate_password_hash(admin_password)
    now = datetime.utcnow().isoformat()

    cur.execute(
        """INSERT INTO users
               (username, password_hash, is_admin, created_at, last_login)
               VALUES (?, ?, ?, ?, ?);""",
        (admin_username, admin_hash, 1, now, now),
    )

    conn.commit()
    conn.close()
    print("Database initialized with default data.")
    print("Admin login -> username: admin | password: admin123")


with app.app_context():
    init_db()


# ----------------- CONTEXT PROCESSORS -----------------

@app.context_processor
def inject_common():
    return {
        "current_year": datetime.now().year
    }


# ----------------- AUTH HELPERS -----------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session or not session.get("is_admin"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Admin access required"}), 403
            flash("Only admin can access this page.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def get_election(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM election WHERE id = 1;")
    return cur.fetchone()


def get_election_status(election_row):
    if not election_row:
        return "No election"
    start = election_row["start_date"]
    end = election_row["end_date"]
    today = date.today()
    try:
        start_d = datetime.strptime(start, "%Y-%m-%d").date() if start else None
        end_d = datetime.strptime(end, "%Y-%m-%d").date() if end else None
    except Exception:
        return "Unknown"
    if start_d and today < start_d:
        return "Upcoming"
    if start_d and end_d and start_d <= today <= end_d:
        return "Ongoing"
    if end_d and today > end_d:
        return "Completed"
    return "Unknown"


# ----------------- HTML ROUTES -----------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm = request.form["confirm"]

        if len(username) < 4:
            flash("Username must be at least 4 characters.", "danger")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Password and confirm password do not match.", "danger")
            return redirect(url_for("register"))

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            password_hash = generate_password_hash(password)
            now = datetime.utcnow().isoformat()
            cur.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?);",
                (username, password_hash, now),
            )
            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken. Choose another one.", "danger")
            return redirect(url_for("register"))
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Step 1: username + password -> generate OTP
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?;", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            otp = f"{random.randint(0, 999999):06d}"
            expires = datetime.utcnow() + timedelta(minutes=5)

            cur.execute(
                "UPDATE users SET otp_code = ?, otp_expires_at = ? WHERE id = ?;",
                (otp, expires.isoformat(), user["id"]),
            )
            conn.commit()
            conn.close()

            print(f"[DEBUG] OTP for {username}: {otp}")
            session["pending_user_id"] = user["id"]
            flash("OTP generated. Check console in this demo.", "info")
            return redirect(url_for("verify_otp"))
        else:
            conn.close()
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending_user_id = session.get("pending_user_id")
    if not pending_user_id:
        flash("No OTP verification pending.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_input = request.form["otp"].strip()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?;", (pending_user_id,))
        user = cur.fetchone()

        if not user:
            conn.close()
            flash("User not found.", "danger")
            session.pop("pending_user_id", None)
            return redirect(url_for("login"))

        otp_code = user["otp_code"]
        otp_expires_at = user["otp_expires_at"]

        if not otp_code or not otp_expires_at:
            conn.close()
            flash("No OTP generated.", "danger")
            session.pop("pending_user_id", None)
            return redirect(url_for("login"))

        try:
            expires_dt = datetime.fromisoformat(otp_expires_at)
        except Exception:
            expires_dt = datetime.utcnow() - timedelta(seconds=1)

        if otp_input != otp_code:
            conn.close()
            flash("Invalid OTP.", "danger")
            return redirect(url_for("verify_otp"))

        if datetime.utcnow() > expires_dt:
            conn.close()
            flash("OTP expired. Login again.", "danger")
            session.pop("pending_user_id", None)
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])

        cur.execute(
            "UPDATE users SET last_login = ?, otp_code = NULL, otp_expires_at = NULL WHERE id = ?;",
            (datetime.utcnow().isoformat(), user["id"]),
        )
        conn.commit()
        conn.close()

        session.pop("pending_user_id", None)
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    election = get_election(conn)
    status = get_election_status(election) if election else "No election"

    candidates = []
    vote_row = None
    has_voted = False

    if election:
        cur.execute("SELECT * FROM candidates;")
        candidates = cur.fetchall()

        cur.execute(
            """SELECT v.*, c.name AS candidate_name, c.party AS candidate_party
                   FROM votes v
                   JOIN candidates c ON v.candidate_id = c.id
                   WHERE v.user_id = ?
                   LIMIT 1;""",
            (user_id,),
        )
        vote_row = cur.fetchone()
        has_voted = vote_row is not None

    conn.close()

    return render_template(
        "dashboard.html",
        election=election,
        status=status,
        candidates=candidates,
        has_voted=has_voted,
        vote_row=vote_row,
    )


@app.route("/vote/<int:candidate_id>", methods=["GET", "POST"])
@login_required
def vote(candidate_id):
    """Record a vote for the given candidate.
    Supports both POST (form) and GET (link) to be extra robust.
    """
    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    print(f"[DEBUG] /vote called: user_id={user_id}, candidate_id={candidate_id}, method={request.method}")

    election = get_election(conn)
    if not election:
        conn.close()
        flash("No election is configured.", "danger")
        return redirect(url_for("dashboard"))

    # Check if user already voted (one vote per user)
    cur.execute("SELECT * FROM votes WHERE user_id = ? LIMIT 1;", (user_id,))
    existing_vote = cur.fetchone()
    if existing_vote:
        conn.close()
        flash("You have already voted.", "danger")
        return redirect(url_for("dashboard"))

    # Verify candidate exists
    cur.execute("SELECT * FROM candidates WHERE id = ?;", (candidate_id,))
    candidate = cur.fetchone()
    if not candidate:
        conn.close()
        flash("Invalid candidate.", "danger")
        return redirect(url_for("dashboard"))

    cur.execute(
        "INSERT INTO votes (user_id, candidate_id, created_at) VALUES (?, ?, ?);",
        (user_id, candidate_id, datetime.utcnow().isoformat()),
    )
    vote_id = cur.lastrowid

    # Append this vote to the blockchain-style audit log
    create_block_for_vote(cur, conn, vote_id)

    conn.close()

    flash("Your vote has been recorded. Thank you!", "success")
    return redirect(url_for("dashboard"))


@app.route("/results")
@admin_required
def results():
    conn = get_db_connection()
    cur = conn.cursor()

    election = get_election(conn)
    if not election:
        conn.close()
        flash("No election configured.", "warning")
        return redirect(url_for("admin_dashboard"))

    cur.execute(
        """SELECT c.id, c.name, c.party, COUNT(v.id) AS votes
               FROM candidates c
               LEFT JOIN votes v ON c.id = v.candidate_id
               GROUP BY c.id, c.name, c.party
               ORDER BY votes DESC;""",
    )
    results_data = cur.fetchall()
    conn.close()

    return render_template("results.html", results=results_data, election=election)


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()

    election = get_election(conn)
    status = get_election_status(election) if election else "No election"

    cur.execute("SELECT COUNT(*) AS cnt FROM users;")
    total_users = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(DISTINCT user_id) AS cnt FROM votes;")
    unique_voters = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) AS cnt FROM votes;")
    total_votes = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) AS cnt FROM candidates;")
    total_candidates = cur.fetchone()["cnt"]

    turnout_percentage = 0.0
    if total_users > 0 and unique_voters > 0:
        turnout_percentage = round((unique_voters / total_users) * 100, 2)

    cur.execute("SELECT * FROM candidates;")
    candidates = cur.fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        election=election,
        status=status,
        total_users=total_users,
        total_votes=total_votes,
        total_candidates=total_candidates,
        unique_voters=unique_voters,
        turnout_percentage=turnout_percentage,
        candidates=candidates,
        elections_list=[election] if election else [],
    )


@app.route("/admin/election", methods=["POST"])
@admin_required
def admin_update_election():
    name = request.form.get("name", "").strip()
    start_date = request.form.get("start_date", "").strip()
    end_date = request.form.get("end_date", "").strip()

    conn = get_db_connection()
    cur = conn.cursor()

    election = get_election(conn)
    if not election:
        cur.execute(
            "INSERT INTO election (id, name, start_date, end_date) VALUES (1, ?, ?, ?);",
            (name or "Election", start_date or None, end_date or None),
        )
    else:
        if not name:
            name = election["name"]
        cur.execute(
            "UPDATE election SET name = ?, start_date = ?, end_date = ? WHERE id = 1;",
            (name or None, start_date or None, end_date or None),
        )

    conn.commit()
    conn.close()

    flash("Election details updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/candidates", methods=["POST"])
@admin_required
def admin_add_candidate():
    name = request.form.get("name", "").strip()
    party = request.form.get("party", "").strip()

    if not name:
        flash("Candidate name is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO candidates (name, party) VALUES (?, ?);",
        (name, party or None),
    )
    conn.commit()
    conn.close()

    flash("Candidate added successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/export-results")
@admin_required
def admin_export_results():
    conn = get_db_connection()
    cur = conn.cursor()

    election = get_election(conn)
    if not election:
        conn.close()
        flash("No election to export.", "danger")
        return redirect(url_for("results"))

    cur.execute(
        """SELECT c.name AS candidate_name,
                      COALESCE(c.party, 'Independent') AS party,
                      COUNT(v.id) AS votes
               FROM candidates c
               LEFT JOIN votes v ON c.id = v.candidate_id
               GROUP BY c.id, c.name, c.party
               ORDER BY votes DESC;"""
    )
    rows = cur.fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Candidate", "Party", "Votes"])
    for row in rows:
        writer.writerow([row["candidate_name"], row["party"], row["votes"]])

    csv_data = output.getvalue()
    filename = f"results_{election['name'].replace(' ', '_')}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


@app.route("/admin/reset-election", methods=["POST"])
@admin_required
def admin_reset_election():
    """Clear all votes but keep users and candidates."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM votes;")
    conn.commit()
    conn.close()
    flash("Election has been reset. All votes were cleared.", "warning")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/candidates/<int:candidate_id>/delete", methods=["POST"])
@admin_required
def admin_delete_candidate(candidate_id):
    """Delete a candidate and all votes associated with them."""
    conn = get_db_connection()
    cur = conn.cursor()

    # Check candidate exists
    cur.execute("SELECT * FROM candidates WHERE id = ?;", (candidate_id,))
    candidate = cur.fetchone()
    if not candidate:
        conn.close()
        flash("Candidate not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    # Delete votes for this candidate
    cur.execute("DELETE FROM votes WHERE candidate_id = ?;", (candidate_id,))
    # Delete candidate
    cur.execute("DELETE FROM candidates WHERE id = ?;", (candidate_id,))
    conn.commit()
    conn.close()

    flash(f"Candidate '{candidate['name']}' has been removed along with their votes.", "warning")
    return redirect(url_for("admin_dashboard"))



def create_block_for_vote(cur, conn, vote_id):
    """Append a new block to the blockchain-style audit log for a given vote_id."""
    import hashlib
    from datetime import datetime as dt

    # Get last block
    cur.execute("SELECT * FROM blocks ORDER BY index_no DESC LIMIT 1;")
    last_block = cur.fetchone()

    index_no = 1 if last_block is None else last_block["index_no"] + 1
    previous_hash = None if last_block is None else last_block["hash"]

    timestamp = dt.utcnow().isoformat()

    data_str = f"{index_no}|{timestamp}|{vote_id}|{previous_hash or ''}"
    block_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    cur.execute(
        """INSERT INTO blocks (index_no, timestamp, vote_id, previous_hash, hash)
               VALUES (?, ?, ?, ?, ?);""",
        (index_no, timestamp, vote_id, previous_hash, block_hash),
    )
    conn.commit()


@app.route("/admin/verify-chain")
@admin_required
def admin_verify_chain():
    """Verify integrity of the vote blockchain.
    If any block has been tampered with, the chain verification fails.
    """
    import hashlib

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM blocks ORDER BY index_no ASC;")
    blocks = cur.fetchall()
    conn.close()

    previous_hash = None
    for b in blocks:
        data_str = f"{b['index_no']}|{b['timestamp']}|{b['vote_id']}|{previous_hash or ''}"
        expected_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
        if expected_hash != b["hash"]:
            flash(f"Blockchain tampering detected at block index {b['index_no']}.", "danger")
            return redirect(url_for("admin_dashboard"))
        previous_hash = b["hash"]

    flash("Blockchain verified: no tampering detected.", "success")
    return redirect(url_for("admin_dashboard"))



def base36encode(num: int) -> str:
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out = ""
    while num > 0:
        num, rem = divmod(num, 36)
        out = chars[rem] + out
    return out or "0"

def mask_user_id(user_id: int) -> str:
    token = (user_id * 997) % 999983
    return f"Voter {base36encode(token)}"

@app.route("/admin/blocks")
@admin_required
def admin_blocks():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT b.index_no, b.timestamp, b.vote_id, b.previous_hash, b.hash,
               v.user_id, v.candidate_id, c.name AS candidate_name, c.party AS candidate_party
        FROM blocks b
        JOIN votes v ON b.vote_id = v.id
        JOIN candidates c ON v.candidate_id = c.id
        ORDER BY b.index_no ASC;
    """)
    rows = cur.fetchall()
    conn.close()

    data = []
    for r in rows:
        data.append(dict(
            index_no=r["index_no"],
            timestamp=r["timestamp"],
            vote_id=r["vote_id"],
            candidate_name=r["candidate_name"],
            candidate_party=r["candidate_party"],
            masked_user=mask_user_id(r["user_id"]),
            previous_hash=r["previous_hash"],
            hash=r["hash"]
        ))

    return render_template("admin_blocks.html", blocks=data)


# ----------------- JSON API -----------------

@app.route("/api/results", methods=["GET"])
@admin_required
def api_results():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """SELECT c.id, c.name, c.party, COUNT(v.id) AS votes
               FROM candidates c
               LEFT JOIN votes v ON c.id = v.candidate_id
               GROUP BY c.id, c.name, c.party
               ORDER BY votes DESC;"""
    )
    results_data = [
        {
            "id": row["id"],
            "name": row["name"],
            "party": row["party"],
            "votes": row["votes"],
        }
        for row in cur.fetchall()
    ]
    conn.close()
    return jsonify({"results": results_data})


# ----------------- ERROR HANDLERS -----------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True)
