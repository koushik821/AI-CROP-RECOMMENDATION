from flask import Flask, render_template, request, redirect, url_for, session, flash
import joblib
import numpy as np
import sqlite3
import hashlib
import os
from datetime import datetime
from functools import wraps
from config import Config

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.config.from_object(Config)

# Load ML model
model = joblib.load(Config.MODEL_PATH)

# Database initialization
def init_db():
    """Initialize the database with required tables"""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Predictions history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            nitrogen REAL,
            phosphorus REAL,
            potassium REAL,
            ph REAL,
            temperature REAL,
            humidity REAL,
            rainfall REAL,
            predicted_crop TEXT,
            prediction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Password hashing
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Database helper functions
def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_email(email):
    """Get user by email"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

def get_user_by_username(username):
    """Get user by username"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def create_user(username, email, password):
    """Create new user"""
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            (username, email, hash_password(password))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def save_prediction(user_id, features, prediction):
    """Save prediction to database"""
    conn = get_db_connection()
    conn.execute(
        '''INSERT INTO predictions 
        (user_id, nitrogen, phosphorus, potassium, ph, temperature, humidity, rainfall, predicted_crop)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (user_id, features[0], features[1], features[2], features[3], 
         features[4], features[5], features[6], prediction)
    )
    conn.commit()
    conn.close()

def get_user_predictions(user_id, limit=10):
    """Get user's prediction history"""
    conn = get_db_connection()
    predictions = conn.execute(
        'SELECT * FROM predictions WHERE user_id = ? ORDER BY prediction_date DESC LIMIT ?',
        (user_id, limit)
    ).fetchall()
    conn.close()
    return predictions

# Routes
@app.route('/')
def landing():
    """Landing page - redirect based on login status"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
        
        # Check if user exists
        if get_user_by_email(email):
            flash('Email already registered', 'error')
            return render_template('signup.html')
        
        if get_user_by_username(username):
            flash('Username already taken', 'error')
            return render_template('signup.html')
        
        # Create user
        if create_user(username, email, password):
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('login.html')
        
        user = get_user_by_email(email)
        
        if user and user['password'] == hash_password(password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    """Crop prediction"""
    try:
        features = [
            float(request.form['N']),
            float(request.form['P']),
            float(request.form['K']),
            float(request.form['pH']),
            float(request.form['temperature']),
            float(request.form['humidity']),
            float(request.form['rainfall'])
        ]
        
        prediction = model.predict([features])[0]
        
        # Save prediction to database
        save_prediction(session['user_id'], features, prediction)
        
        return render_template('dashboard.html', 
                             username=session.get('username'),
                             prediction_text=f"✅ Recommended Crop: {prediction}",
                             features=features)
    except Exception as e:
        return render_template('dashboard.html', 
                             username=session.get('username'),
                             prediction_text=f"❌ Error: {str(e)}")

@app.route('/history')
@login_required
def history():
    """View prediction history"""
    predictions = get_user_predictions(session['user_id'])
    return render_template('history.html', 
                         username=session.get('username'),
                         predictions=predictions)

@app.route('/delete_prediction/<int:pred_id>', methods=['POST'])
@login_required
def delete_prediction(pred_id):
    """Delete a prediction from history"""
    conn = get_db_connection()
    conn.execute('DELETE FROM predictions WHERE id = ? AND user_id = ?', 
                (pred_id, session['user_id']))
    conn.commit()
    conn.close()
    flash('Prediction deleted successfully', 'success')
    return redirect(url_for('history'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)