from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Used for session management

# Function to connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect('vulnerable_app.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            feedback TEXT NOT NULL
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin123')")
    conn.commit()
    conn.close()

# Login Page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Vulnerable SQL query (intentionally insecure)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()

        if result:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password!")

    return render_template('login.html')


# Dashboard Page (Accessible only after login)
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

# Feedback Form (Vulnerable to XSS and HTML Injection)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        feedback = request.form['feedback']

        # Pass user input directly to the template (vulnerable to XSS and HTML injection)
        return render_template('feedback.html', name=name, feedback=feedback)
    
    return render_template('feedback.html', name=None, feedback=None)




# Ping Page (Vulnerable to Command Injection)
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        ip = request.form['ip']
        # Vulnerable to command injection
        output = os.popen(f"ping -c 1 {ip}").read()
        return render_template('ping.html', result=output)

    return render_template('ping.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
