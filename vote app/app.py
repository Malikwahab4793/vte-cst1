# app.py
from flask import Flask, request, redirect, url_for, render_template_string, session, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
import secrets, os, json, io
import pandas as pd
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# File paths
STAFF_FILE = 'staff.json'
ADMIN_FILE = 'admins.json'
VOTES_FILE = 'votes.json'
TOKENS_FILE = 'tokens.json'

# Ensure files exist
for f in [STAFF_FILE, ADMIN_FILE, VOTES_FILE, TOKENS_FILE]:
    if not os.path.exists(f):
        with open(f, 'w') as fh:
            json.dump([], fh)

# Helpers for JSON read/write
def read_json(path):
    with open(path, 'r') as fh:
        try:
            return json.load(fh)
        except:
            return []

def write_json(path, data):
    with open(path, 'w') as fh:
        json.dump(data, fh, indent=2, default=str)

# Admin-required decorator
def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if session.get('admin_email'):
            return fn(*a, **kw)
        return redirect(url_for('admin_login'))
    return wrapper

# HTML template (fixed: added |safe)
base_html = """
<!doctype html>
<title>Voting App</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<nav>
  <a href="{{ url_for('index') }}">Home</a>
  {% if session.get('admin_email') %}
    <strong>Admin: {{ session.get('admin_email') }}</strong> |
    <a href="{{ url_for('admin_dashboard') }}">Dashboard</a> |
    <a href="{{ url_for('admin_logout') }}">Logout</a>
  {% else %}
    <a href="{{ url_for('admin_login') }}">Admin Login</a> |
    <a href="{{ url_for('admin_signup') }}">Admin Signup</a>
  {% endif %}
</nav>
<main>
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <ul>
      {% for m in messages %}
        <li><strong>{{ m }}</strong></li>
      {% endfor %}
      </ul>
    {% endif %}
  {% endwith %}
  {{ body|safe }}
</main>
"""

#index
@app.route('/')
def index():
    body = """
    <h1>Voting App</h1>
    <p>Admin can signup/login and create a registration link for staff.</p>
    <p>If you are staff and received a registration link, open it to register yourself.</p>
    """
    return render_template_string(base_html, body=body)

# Admin signup
@app.route('/admin/signup', methods=['GET','POST'])
def admin_signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        admins = read_json(ADMIN_FILE)
        if any(a['email'] == email for a in admins):
            flash('Admin with this email already exists.')
            return redirect(url_for('admin_signup'))
        admins.append({
            'email': email,
            'password_hash': generate_password_hash(password),
            'created_at': str(datetime.utcnow())
        })
        write_json(ADMIN_FILE, admins)
        flash('Admin registered. Please login.')
        return redirect(url_for('admin_login'))
    body = """
    <h2>Admin Signup</h2>
    <form method="post">
      <label>Email: <input name="email" required></label><br>
      <label>Password: <input name="password" type="password" required></label><br>
      <button type="submit">Signup</button>
    </form>
    """
    return render_template_string(base_html, body=body)

# Admin login
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        admins = read_json(ADMIN_FILE)
        admin = next((a for a in admins if a['email']==email), None)
        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_email'] = email
            flash('Logged in as admin.')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials.')
    body = """
    <h2>Admin Login</h2>
    <form method="post">
      <label>Email: <input name="email" required></label><br>
      <label>Password: <input name="password" type="password" required></label><br>
      <button type="submit">Login</button>
    </form>
    """
    return render_template_string(base_html, body=body)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_email', None)
    flash('Logged out.')
    return redirect(url_for('index'))

# Admin dashboard
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    staff = read_json(STAFF_FILE)
    votes = read_json(VOTES_FILE)
    tokens = read_json(TOKENS_FILE)
    # Build simple table
    table_html = "<h2>Staff registrations</h2>"
    if not staff:
        table_html += "<p>No staff registered yet.</p>"
    else:
        table_html += "<table><thead><tr><th>Name</th><th>Father Name</th><th>NIC</th><th>Email</th><th>Registered At</th></tr></thead><tbody>"
        for s in staff:
            table_html += f"<tr><td>{s.get('name','')}</td><td>{s.get('father_name','')}</td><td>{s.get('nic','')}</td><td>{s.get('email','')}</td><td>{s.get('registered_at','')}</td></tr>"
        table_html += "</tbody></table>"
    # Votes summary
    vote_html = "<h2>Votes</h2>"
    if not votes:
        vote_html += "<p>No votes yet.</p>"
    else:
        summary = {}
        for v in votes:
            option = v.get('choice','')
            summary[option] = summary.get(option,0) + 1
        vote_html += "<ul>"
        for k,v in summary.items():
            vote_html += f"<li>{k}: {v}</li>"
        vote_html += "</ul>"
    # Tokens list
    token_html = "<h2>Registration Links (Tokens)</h2>"
    token_html += "<ul>"
    for t in tokens:
        token_html += f"<li>{t.get('token')} - expires: {t.get('expires_at','')} - created: {t.get('created_at','')}</li>"
    token_html += "</ul>"
    # Actions
    actions = f"""
    <h2>Actions</h2>
    <form action="{url_for('create_token')}" method="post">
      <label>Optional expire in minutes (0 = no expiry): <input name="expiry_minutes" value="0" type="number" min="0"></label>
      <button type="submit">Create registration link</button>
    </form>
    <p>Download data:</p>
    <a href="{url_for('download_json')}">Download staff JSON</a> |
    <a href="{url_for('download_excel')}">Download staff Excel (.xlsx)</a> |
    <a href="{url_for('download_votes_json')}">Download votes JSON</a> |
    <a href="{url_for('download_votes_excel')}">Download votes Excel (.xlsx)</a>
    """
    body = table_html + vote_html + token_html + actions
    return render_template_string(base_html, body=body)

# Create token
@app.route('/admin/create_token', methods=['POST'])
@admin_required
def create_token():
    expiry = int(request.form.get('expiry_minutes') or 0)
    token = secrets.token_urlsafe(16)
    tokens = read_json(TOKENS_FILE)
    entry = {
        'token': token,
        'created_at': str(datetime.utcnow()),
        'created_by': session.get('admin_email'),
        'expires_at': None
    }
    if expiry>0:
        entry['expires_at'] = str(datetime.utcnow() + pd.to_timedelta(expiry, unit='m'))
    tokens.append(entry)
    write_json(TOKENS_FILE, tokens)
    flash(f"Token created. Share this registration link with staff: {request.url_root.rstrip('/')}/register/{token}")
    return redirect(url_for('admin_dashboard'))

# Staff registration via token
@app.route('/register/<token>', methods=['GET','POST'])
def register(token):
    tokens = read_json(TOKENS_FILE)
    token_entry = next((t for t in tokens if t['token']==token), None)
    if not token_entry:
        return render_template_string(base_html, body=f"<h2>Invalid registration link.</h2>")
    if token_entry.get('expires_at'):
        if datetime.fromisoformat(token_entry['expires_at']) < datetime.utcnow():
            return render_template_string(base_html, body=f"<h2>Registration link expired.</h2>")
    if request.method == 'POST':
        name = request.form['name'].strip()
        father_name = request.form['father_name'].strip()
        nic = request.form['nic'].strip()
        email = request.form['email'].strip().lower()
        staff = read_json(STAFF_FILE)
        if any(s.get('nic')==nic or s.get('email')==email for s in staff):
            flash('A staff with this NIC or email already registered.')
            return redirect(request.url)
        staff.append({
            'name': name,
            'father_name': father_name,
            'nic': nic,
            'email': email,
            'registered_at': str(datetime.utcnow()),
            'registered_from_token': token
        })
        write_json(STAFF_FILE, staff)
        flash('Registration successful. You may now vote if voting is open.')
        return redirect(url_for('index'))
    body = f"""
    <h2>Staff Registration</h2>
    <p>Registering using token: <code>{token}</code></p>
    <form method="post">
      <label>Name: <input name="name" required></label><br>
      <label>Father Name: <input name="father_name" required></label><br>
      <label>NIC: <input name="nic" required></label><br>
      <label>Email: <input name="email" required></label><br>
      <button type="submit">Register</button>
    </form>
    """
    return render_template_string(base_html, body=body)

# Voting
@app.route('/vote', methods=['GET','POST'])
def vote():
    if request.method == 'POST':
        nic = request.form['nic'].strip()
        choice = request.form['choice'].strip()
        staff = read_json(STAFF_FILE)
        if not any(s.get('nic')==nic for s in staff):
            flash('NIC not found. Please register first.')
            return redirect(url_for('vote'))
        votes = read_json(VOTES_FILE)
        if any(v.get('nic')==nic for v in votes):
            flash('You have already voted.')
            return redirect(url_for('vote'))
        votes.append({
            'nic': nic,
            'choice': choice,
            'voted_at': str(datetime.utcnow())
        })
        write_json(VOTES_FILE, votes)
        flash('Vote recorded. Thank you!')
        return redirect(url_for('index'))
    body = """
    <h2>Vote</h2>
    <form method="post">
      <label>Your NIC: <input name="nic" required></label><br>
      <label>Choice:
        <select name="choice">
          <option>Option A</option>
          <option>Option B</option>
          <option>Option C</option>
        </select>
      </label><br>
      <button type="submit">Submit Vote</button>
    </form>
    """
    return render_template_string(base_html, body=body)

# Downloads
@app.route('/admin/download/staff.json')
@admin_required
def download_json():
    data = read_json(STAFF_FILE)
    return send_file(io.BytesIO(json.dumps(data, indent=2).encode('utf-8')),
                     as_attachment=True,
                     download_name='staff.json',
                     mimetype='application/json')

@app.route('/admin/download/staff.xlsx')
@admin_required
def download_excel():
    data = read_json(STAFF_FILE)
    if not data:
        df = pd.DataFrame(columns=['name','father_name','nic','email','registered_at'])
    else:
        df = pd.DataFrame(data)
    cols = [c for c in ['name','father_name','nic','email','registered_at'] if c in df.columns] + [c for c in df.columns if c not in ['name','father_name','nic','email','registered_at']]
    df = df[cols]
    bio = io.BytesIO()
    with pd.ExcelWriter(bio, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='staff')
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name='staff.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/admin/download/votes.json')
@admin_required
def download_votes_json():
    data = read_json(VOTES_FILE)
    return send_file(io.BytesIO(json.dumps(data, indent=2).encode('utf-8')),
                     as_attachment=True,
                     download_name='votes.json',
                     mimetype='application/json')

@app.route('/admin/download/votes.xlsx')
@admin_required
def download_votes_excel():
    data = read_json(VOTES_FILE)
    df = pd.DataFrame(data) if data else pd.DataFrame(columns=['nic','choice','voted_at'])
    bio = io.BytesIO()
    with pd.ExcelWriter(bio, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='votes')
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name='votes.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    app.run(debug=True)
