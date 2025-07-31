from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import uuid

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS mechanics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        expertise TEXT NOT NULL,
        location TEXT NOT NULL,
        contact TEXT NOT NULL,
        availability TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        mechanic_id INTEGER,
        issue TEXT NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (mechanic_id) REFERENCES mechanics(id)
    )''')
    # Insert sample mechanics
    c.execute("SELECT COUNT(*) FROM mechanics")
    if c.fetchone()[0] == 0:
        sample_mechanics = [
            ('John Doe', 'Engine Repair', 'New York', '555-1234', 'Available'),
            ('Jane Smith', 'Tire Services', 'Los Angeles', '555-5678', 'Available'),
            ('Mike Brown', 'Brake Repair', 'Chicago', '555-9012', 'Busy')
        ]
        c.executemany('INSERT INTO mechanics (name, expertise, location, contact, availability) VALUES (?, ?, ?, ?, ?)', sample_mechanics)
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password, user[1].encode('utf-8')):
            session['user_id'] = user[0]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        email = request.form['email']
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password.decode('utf-8'), email))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username, email FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    c.execute('SELECT * FROM mechanics WHERE availability = ?', ('Available',))
    mechanics = c.fetchall()
    c.execute('SELECT r.id, r.issue, r.status, m.name FROM requests r JOIN mechanics m ON r.mechanic_id = m.id WHERE r.user_id = ?', (session['user_id'],))
    requests = c.fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, mechanics=mechanics, requests=requests)

@app.route('/mechanics', methods=['GET', 'POST'])
def mechanics():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    search_query = request.form.get('search', '')
    if search_query:
        c.execute('SELECT * FROM mechanics WHERE location LIKE ? OR expertise LIKE ?', (f'%{search_query}%', f'%{search_query}%'))
    else:
        c.execute('SELECT * FROM mechanics')
    mechanics = c.fetchall()
    conn.close()
    return render_template('mechanics.html', mechanics=mechanics, search_query=search_query)

@app.route('/request_service/<int:mechanic_id>', methods=['GET', 'POST'])
def request_service(mechanic_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        issue = request.form['issue']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO requests (user_id, mechanic_id, issue, status) VALUES (?, ?, ?, ?)', 
                 (session['user_id'], mechanic_id, issue, 'Pending'))
        conn.commit()
        conn.close()
        flash('Service request submitted!', 'success')
        return redirect(url_for('dashboard'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT name FROM mechanics WHERE id = ?', (mechanic_id,))
    mechanic = c.fetchone()
    conn.close()
    return render_template('request_service.html', mechanic_id=mechanic_id, mechanic_name=mechanic[0])

if __name__ == '__main__':
    init_db()
    app.run(debug=True)