from flask import Flask, render_template, request, url_for, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'racecar'

# Initialize the database and create the 'users' and 'messages' tables
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create users table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS users
              (id INTEGER PRIMARY KEY, username TEXT,
               password TEXT, role TEXT DEFAULT 'user')''')
    
    # Create messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
              (id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER,
               message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
               FOREIGN KEY (sender_id) REFERENCES users(id),
               FOREIGN KEY (receiver_id) REFERENCES users(id))''')

    # Check if a superadmin exists, if not, create one
    c.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
    if c.fetchone()[0] == 0:
        c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
                  ('maxin', generate_password_hash('matrix@60'), 'superadmin'))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'username' in session:
        return render_template('main.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users(username, password) VALUES(?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            role = user[3]
            if role == 'admin':
                return redirect(url_for('admin'))
            elif role == 'user':
                return redirect(url_for('home'))
            elif role == 'superadmin':
                return redirect(url_for('superadmin'))
        return "Invalid credentials. Please try again."
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/update_password', methods=['POST', 'GET'])
def update_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        hashed_new_password = generate_password_hash(new_password)

        # Verify the current password
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], current_password):
            # Update the password if the current password is correct
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_new_password, session['username']))
            conn.commit()
            conn.close()
            return redirect(url_for('home'))
        else:
            return "Incorrect current password. Please try again."

    return render_template('update_password.html')

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']

        # Verify the current password
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], current_password):
            # Delete the account if the current password is correct
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('DELETE FROM users WHERE username = ?', (session['username'],))
            conn.commit()
            conn.close()
            session.pop('username', None)
            return redirect(url_for('login'))
        else:
            return "Incorrect password. Please try again."

    return render_template('delete_account.html')

@app.route('/admin')
def admin():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    return render_template('admin.html')

@app.route('/superadmin')
def superadmin():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session['username'] != 'superadmin':
        return redirect(url_for('home'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, role FROM users')
    users = c.fetchall()
    conn.close()
    
    return render_template('superadmin.html', users=users)

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Fetch user info from the session
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, role FROM users WHERE username = ?', (session['username'],))
    user = c.fetchone()
    user_id = user[0]
    role = user[1]
    conn.close()

    # Fetch messages for the user
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''SELECT messages.id, users.username, messages.message, messages.timestamp
                 FROM messages
                 JOIN users ON messages.sender_id = users.id
                 WHERE receiver_id = ? ORDER BY timestamp DESC''', (user_id,))
    messages = c.fetchall()

    # Handle sending a message
    if request.method == 'POST':
        recipient = request.form['recipient']
        message = request.form['message']
        
        # Check if the user has reached the message limit based on role
        if role == 'user':
            # Get the number of messages the user has sent in the current session
            c.execute('SELECT COUNT(*) FROM messages WHERE sender_id = ?', (user_id,))
            message_count = c.fetchone()[0]
            if message_count >= 5:
                return "Message limit reached. Please try again later."

        # Insert message into database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''INSERT INTO messages(sender_id, receiver_id, message) 
                     VALUES(?, ?, ?)''', (user_id, recipient, message))
        conn.commit()
        conn.close()

        return redirect(url_for('messages'))

    return render_template('messages.html', messages=messages, role=role)

@app.route('/admin/messages')
def admin_messages():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''SELECT messages.id, sender.username AS sender, receiver.username AS receiver, 
                messages.message, messages.timestamp
                FROM messages
                JOIN users AS sender ON messages.sender_id = sender.id
                JOIN users AS receiver ON messages.receiver_id = receiver.id''')
    all_messages = c.fetchall()
    conn.close()
    
    return render_template('admin_messages.html', messages=all_messages)

@app.route('/change_role/<int:user_id>/<new_role>')
def change_role(user_id, new_role):
    if 'username' not in session or session['username'] != 'superadmin':
        return redirect(url_for('login'))
    
    if new_role not in ['user', 'admin', 'superadmin']:
        return "Invalid role", 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('superadmin'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
