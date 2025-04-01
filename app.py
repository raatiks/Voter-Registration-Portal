# app.py
from flask import Flask, render_template, request, redirect, url_for, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from faker import Faker
import bcrypt
import pandas as pd
from io import BytesIO
import os
from flask import flash
from markupsafe import escape

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voters.db'
app.config['SECRET_KEY'] = os.getenv(
    'SECRET_KEY', 'default-secret-key')  # Use .env in production

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

# Database Models


class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hashed_id = db.Column(db.String(200), unique=True)
    community = db.Column(db.String(50))


class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))


# Create tables and admin user
with app.app_context():
    db.create_all()
    if not Admin.query.filter_by(username="admin").first():
        admin = Admin(
            username="admin",
            password_hash=generate_password_hash(
                "securepassword123")
        )
        db.session.add(admin)
        db.session.commit()

# Flask-Login Configuration


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))

# Routes


@app.route('/')
def index():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    # Sanitize inputs
    from markupsafe import escape
    name = escape(request.form['name'])
    voter_id = request.form['voter_id'].encode('utf-8')
    community = request.form['community']

    # Community validation
    valid_communities = ['Remote Community A', 'First Nations Reserve']
    if community not in valid_communities:
        flash('Invalid community selection', 'danger')
        return redirect(url_for('index'))

    # Hash the voter ID
    hashed_id = bcrypt.hashpw(voter_id, bcrypt.gensalt()).decode('utf-8')

    # Duplicate check
    existing_voter = Voter.query.filter_by(hashed_id=hashed_id).first()
    if existing_voter:
        flash('Voter ID already exists', 'danger')
        return redirect(url_for('index'))

    # Create new voter if all validations pass
    new_voter = Voter(
        name=name,
        hashed_id=hashed_id,
        community=community
    )

    db.session.add(new_voter)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('Registration failed. Please try again.', 'danger')
        return redirect(url_for('index'))

    return redirect(url_for('success'))


@app.route('/success')
def success():
    return "Registration Successful!"


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            return redirect(url_for('admin'))
        return "Invalid credentials"
    return render_template('admin_login.html')


@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin')
@login_required
def admin():
    voters = Voter.query.all()
    return render_template('admin.html', voters=voters)


@app.route('/report')
@login_required
def report():
    voters = Voter.query.all()
    # Explicitly define columns to handle empty data
    df = pd.DataFrame(
        [{"community": v.community, "name": v.name} for v in voters],
        columns=['community', 'name']
    )
    report = df.groupby('community').size().reset_index(name='Registrations')
    return render_template('report.html', tables=[report.to_html(classes='data')])


@app.route('/report/pdf')
@login_required
def pdf_report():
    voters = Voter.query.all()
    df = pd.DataFrame([{"community": v.community, "name": v.name}
                       for v in voters], columns=['community', 'name'])
    report = df.groupby('community').size().reset_index(name='Registrations')

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.drawString(100, 750, "Voter Registration Report")

    y = 700
    for _, row in report.iterrows():
        p.drawString(100, y, f"{row['community']}: {row['Registrations']}")
        y -= 20

    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf')


@app.route('/test-data', methods=['GET', 'POST'])
@login_required
def test_data():
    if request.method == 'POST':
        fake = Faker()
        try:
            for _ in range(100):
                name = fake.name()
                voter_id = fake.ssn().replace("-", "").encode("utf-8")
                community = fake.random_element(
                    ["Remote Community A", "First Nations Reserve"])
                hashed_id = bcrypt.hashpw(
                    voter_id, bcrypt.gensalt()).decode("utf-8")
                voter = Voter(name=name, hashed_id=hashed_id,
                              community=community)
                db.session.add(voter)
            db.session.commit()
            flash('Successfully created 100 test entries!', 'success')
        except Exception as e:
            flash(f'Error creating test data: {str(e)}', 'danger')
        return redirect(url_for('admin'))
    return redirect(url_for('admin'))


@app.route('/verify/<int:voter_id>')
@login_required
def verify(voter_id):
    voter = Voter.query.get(voter_id)
    if not voter:
        return "Voter not found"
    return f"Encrypted ID: {voter.hashed_id}"


if __name__ == '__main__':
    app.run(debug=True)
