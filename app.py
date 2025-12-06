import os
import io
import sqlite3
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime, timedelta
from functools import wraps
from vulncheck_api import VulnCheckAPI
from user import User

load_dotenv()

app = Flask(__name__)

# Configuration
#app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.secret_key = os.getenv("SECRET_KEY")

app.config['VULNCHECK_API_KEY'] = os.getenv("VULNCHECK_API_KEY")
app.config['VULNCHECK_BASE_URL'] = os.getenv("VULNCHECK_BASE_URL") or 'https://api.vulncheck.com/v3'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)


# SQLite Configuration
DATABASE = os.environ.get('DATABASE_PATH', 'vulncheck.db')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

def get_db():
    """Get database connection for current request"""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.before_request
def setup_vulncheck_api():
    """Set up VulnCheckAPI instance in the g variable."""
    if 'vulncheck_api' not in g:
        g.vulncheck_api = VulnCheckAPI(app.config['VULNCHECK_API_KEY'], app.config['VULNCHECK_BASE_URL'])

@app.teardown_appcontext
def close_db(error):
    """Close database connection at end of request"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def dict_from_row(row):
    """Convert sqlite3.Row to dictionary"""
    return dict(zip(row.keys(), row)) if row else None

def init_database():
    """Initialize database tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Assets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            cpe_string TEXT,
            ip_address TEXT,
            software TEXT,
            version TEXT,
            criticality TEXT,
            added_date DATE,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Vulnerabilities table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            asset_id INTEGER,
            severity TEXT,
            cvss_score REAL,
            description TEXT,
            exploit_available INTEGER,
            published_date DATE,
            status TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        )
    """)
    
    # Create default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    result = cursor.fetchone()
    if result[0] == 0:
        admin_password = generate_password_hash('admin123')
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            ('admin', 'admin@acmefinancial.com', admin_password)
        )
        print("Default admin user created: username='admin', password='admin123'")
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")


def sync_vulnerabilities_for_asset(asset_id):
    """Sync vulnerabilities from VulnCheck for a specific asset"""
    app.logger.info(f"Syncing vulnerabilities for asset ID: {asset_id}")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
    asset_row = cursor.fetchone()
    
    if not asset_row:
        return {'error': 'Asset not found'}
    
    asset = dict_from_row(asset_row)
    
    # Build CPE string (simplified - you may need to adjust based on your asset data)
    #cpe = f"cpe:2.3:a:*:{asset['software']}:{asset['version']}:*:*:*:*:*:*:*"
    cpe = asset['cpe_string']

    # Search VulnCheck for vulnerabilities
    vuln_data = g.vulncheck_api.search_vulnerabilities_by_cpe(cpe)
    
    if 'error' in vuln_data:
        return vuln_data
    
    synced_count = 0
    data = vuln_data.get('data', [])
    
    for vuln in data[:50]:  # Limit to 50 vulnerabilities
        cve_id = vuln.get('cve_id', '')
        
        # Check if exploit is available
        exploit_info = g.vulncheck_api.get_exploit_info(cve_id)
        exploit_available = 1 if len(exploit_info.get('data', [])) > 0 else 0
        
        # Insert or update vulnerability
        cursor.execute("""
            INSERT OR REPLACE INTO vulnerabilities 
            (cve_id, asset_id, severity, cvss_score, description, exploit_available, published_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            asset_id,
            vuln.get('severity', 'Unknown'),
            vuln.get('cvss_score', 0.0),
            vuln.get('description', '')[:500],
            exploit_available,
            vuln.get('published_date', datetime.now().strftime('%Y-%m-%d')),
            'Open'
        ))
        synced_count += 1
    
    conn.commit()
    return {'success': True, 'synced_count': synced_count}

def create_vulns_pdf(vulnerabilities):
    """Create a PDF bytes buffer from a list of vulnerability dicts (ReportLab)."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("Vulnerabilities Report", styles['Title']))
    elements.append(Spacer(1, 12))

    # Table header
    data = [["CVE", "Asset", "Severity", "CVSS", "Exploit", "Status", "Published", "Description"]]

    # Rows
    for v in vulnerabilities:
        cve = v.get('cve_id', '')
        asset = v.get('asset_name', '') or str(v.get('asset_id', ''))
        severity = v.get('severity', '')
        cvss = f"{v.get('cvss_score', '')}"
        exploit = "Yes" if int(v.get('exploit_available', 0) or 0) == 1 else "No"
        status = v.get('status', '')
        published = v.get('published_date', '') or ''
        description = v.get('description', '') or ''
        # Truncate description for table readability
        if len(description) > 200:
            description = description[:197] + "..."
        data.append([cve, asset, severity, cvss, exploit, status, published, description])

    # Create table
    table = Table(data, colWidths=[80, 80, 55, 40, 50, 55, 60, 140])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),  # header background
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (3, 1), (3, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('INNERGRID', (0,0), (-1,-1), 0.25, colors.gray),
        ('BOX', (0,0), (-1,-1), 0.25, colors.gray),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f7fafc')]),
    ]))

    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

# Routes
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get statistics
    cursor.execute("SELECT COUNT(*) FROM assets WHERE user_id = ?", (current_user.id,))
    total_assets = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT COUNT(DISTINCT v.id)
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE a.user_id = ? AND v.status = 'Open'
    """, (current_user.id,))
    total_vulns = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT COUNT(DISTINCT v.id)
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE a.user_id = ? AND v.severity = 'Critical' AND v.status = 'Open'
    """, (current_user.id,))
    critical_vulns = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT COUNT(DISTINCT v.id)
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE a.user_id = ? AND v.exploit_available = 1 AND v.status = 'Open'
    """, (current_user.id,))
    exploitable_vulns = cursor.fetchone()[0]
    
    # Get recent vulnerabilities
    cursor.execute("""
        SELECT v.*, a.name as asset_name 
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE a.user_id = ? AND v.status = 'Open'
        ORDER BY v.cvss_score DESC, v.last_updated DESC
        LIMIT 10
    """, (current_user.id,))
    recent_vulns = [dict_from_row(row) for row in cursor.fetchall()]
    
    # Get assets by criticality
    cursor.execute("""
        SELECT criticality, COUNT(*) as count
        FROM assets
        WHERE user_id = ?
        GROUP BY criticality
    """, (current_user.id,))
    assets_by_criticality = [dict_from_row(row) for row in cursor.fetchall()]
    
    stats = {
        'total_assets': total_assets,
        'total_vulns': total_vulns,
        'critical_vulns': critical_vulns,
        'exploitable_vulns': exploitable_vulns,
        'recent_vulns': recent_vulns,
        'assets_by_criticality': assets_by_criticality
    }
    
    return render_template('dashboard.html', stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    app.logger.info("Login route accessed")
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        
        if user_row and check_password_hash(user_row[3], password):
            user = User(user_row[0], user_row[1], user_row[2])
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if username or email exists
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            flash('Username or email already exists', 'error')
            return render_template('register.html')
        
        # Create user
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/inventory')
@login_required
def inventory():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE user_id = ? ORDER BY added_date DESC", (current_user.id,))
    assets = [dict_from_row(row) for row in cursor.fetchall()]
    
    return render_template('inventory.html', assets=assets)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_asset():
    if request.method == 'POST':
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO assets (name, type, cpe_string, ip_address, software, version, criticality, added_date, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request.form['name'],
            request.form['type'],
            request.form['cpe_string'],
            request.form['ip_address'],
            request.form['software'],
            request.form['version'],
            request.form['criticality'],
            datetime.now().strftime('%Y-%m-%d'),
            current_user.id
        ))
        conn.commit()
        asset_id = cursor.lastrowid
        
        flash('Asset added successfully!', 'success')
        
        # Optionally sync vulnerabilities
        if request.form.get('sync_vulns'):
            result = sync_vulnerabilities_for_asset(asset_id)
            if 'error' not in result:
                flash(f"Synced {result['synced_count']} vulnerabilities from VulnCheck", 'success')
        
        return redirect(url_for('inventory'))
    
    return render_template('add_asset.html')

@app.route('/inventory/edit/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE id = ? AND user_id = ?", (asset_id, current_user.id))
    asset_row = cursor.fetchone()
    
    if not asset_row:
        flash('Asset not found', 'error')
        return redirect(url_for('inventory'))
    
    asset = dict_from_row(asset_row)
    
    if request.method == 'POST':
        cursor.execute("""
            UPDATE assets 
            SET name = ?, type = ?, cpe_string = ?, ip_address = ?, software = ?, version = ?, criticality = ?
            WHERE id = ? AND user_id = ?
        """, (
            request.form['name'],
            request.form['type'],
            request.form['cpe_string'],
            request.form['ip_address'],
            request.form['software'],
            request.form['version'],
            request.form['criticality'],
            asset_id,
            current_user.id
        ))
        conn.commit()
        
        flash('Asset updated successfully!', 'success')
        return redirect(url_for('inventory'))
    
    return render_template('edit_asset.html', asset=asset)

@app.route('/inventory/delete/<int:asset_id>')
@login_required
def delete_asset(asset_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assets WHERE id = ? AND user_id = ?", (asset_id, current_user.id))
    conn.commit()
    
    flash('Asset deleted successfully!', 'success')
    return redirect(url_for('inventory'))

@app.route('/inventory/sync/<int:asset_id>')
@login_required
def sync_asset_vulnerabilities(asset_id):
    # Verify asset belongs to user
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM assets WHERE id = ? AND user_id = ?", (asset_id, current_user.id))
    if not cursor.fetchone():
        return jsonify({'error': 'Asset not found'}), 404
    
    result = sync_vulnerabilities_for_asset(asset_id)
    
    if 'error' in result:
        flash(f"Error syncing vulnerabilities: {result['error']}", 'error')
    else:
        flash(f"Successfully synced {result['synced_count']} vulnerabilities", 'success')
    
    return redirect(url_for('inventory'))

@app.route('/vulnerabilities')
@login_required
def vulnerabilities_view():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's assets
    cursor.execute("SELECT * FROM assets WHERE user_id = ?", (current_user.id,))
    assets = [dict_from_row(row) for row in cursor.fetchall()]
    
    # Get vulnerabilities for user's assets
    cursor.execute("""
        SELECT v.*, a.name as asset_name 
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE a.user_id = ?
        ORDER BY v.cvss_score DESC, v.last_updated DESC
    """, (current_user.id,))
    vulnerabilities = [dict_from_row(row) for row in cursor.fetchall()]
    
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities, assets=assets)

@app.route('/api/vulnerabilities/<int:asset_id>')
@login_required
def get_asset_vulnerabilities(asset_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT v.* 
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE v.asset_id = ? AND a.user_id = ?
    """, (asset_id, current_user.id))
    vulnerabilities = [dict_from_row(row) for row in cursor.fetchall()]
    
    return jsonify(vulnerabilities)

@app.route('/vulnerabilities/export')
@login_required
def export_vulnerabilities_pdf():
    """Export all vulnerabilities for current user to PDF."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT v.*, a.name as asset_name
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE a.user_id = ?
        ORDER BY v.cvss_score DESC, v.last_updated DESC
    """, (current_user.id,))
    vulnerabilities = [dict_from_row(row) for row in cursor.fetchall()]

    pdf_bytes = create_vulns_pdf(vulnerabilities)
    return send_file(io.BytesIO(pdf_bytes),
                     mimetype='application/pdf',
                     as_attachment=True,
                     download_name='vulnerabilities_report.pdf')


@app.route('/vulnerabilities/export/<int:asset_id>')
@login_required
def export_asset_vulnerabilities_pdf(asset_id):
    """Export vulnerabilities for a single asset to PDF (must belong to current user)."""
    conn = get_db()
    cursor = conn.cursor()
    # Verify asset ownership
    cursor.execute("SELECT id, name FROM assets WHERE id = ? AND user_id = ?", (asset_id, current_user.id))
    asset_row = cursor.fetchone()
    if not asset_row:
        flash('Asset not found or not accessible', 'error')
        return redirect(url_for('inventory'))

    cursor.execute("""
        SELECT v.*, a.name as asset_name
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE v.asset_id = ? AND a.user_id = ?
        ORDER BY v.cvss_score DESC, v.last_updated DESC
    """, (asset_id, current_user.id))
    vulnerabilities = [dict_from_row(row) for row in cursor.fetchall()]

    pdf_bytes = create_vulns_pdf(vulnerabilities)
    filename = f"vulnerabilities_asset_{asset_id}.pdf"
    return send_file(io.BytesIO(pdf_bytes),
                     mimetype='application/pdf',
                     as_attachment=True,
                     download_name=filename)

if __name__ == '__main__':
    init_database()
    app.run(debug=True)