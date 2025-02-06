from flask import Flask, render_template, request, url_for, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'racecar'

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, 
                    username TEXT, 
                    password TEXT, 
                    role TEXT DEFAULT 'user')''')
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    
    # if 'blocked' not in columns:
    #     c.execute('ALTER TABLE users ADD COLUMN blocked INTEGER DEFAULT 0')
    
    c.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
    superadmin_count = c.fetchone()[0]
    c.execute('''SELECT COUNT(*) FROM users WHERE role = "admin"''')
    admin_count = c.fetchone()[0]

    if superadmin_count == 0:
        c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
                  ('maxin', generate_password_hash('matrix@60'), 'superadmin'))
    
    if admin_count == 0:
        admin_users = [
            ('hill', generate_password_hash('789456'), 'admin'),
            ('admin2', generate_password_hash('123456'), 'admin'),
            ('admin3', generate_password_hash('123456'), 'admin'),
            ('admin4', generate_password_hash('123456'), 'admin'),
            ('admin5', generate_password_hash('123456'), 'admin')
        ]
        c.executemany('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''', admin_users)
    
    user_count = len([1 for user in c.execute("SELECT role FROM users WHERE role = 'user'")])
    if user_count == 0:
        user_users = [
            ('user1', generate_password_hash('456789'), 'user'),
            ('user2', generate_password_hash('456789'), 'user'),
            ('user3', generate_password_hash('456789'), 'user'),
            ('user4', generate_password_hash('456789'), 'user'),
            ('user5', generate_password_hash('456789'), 'user'),
            ('user6', generate_password_hash('456789'), 'user'),
            ('user7', generate_password_hash('456789'), 'user'),
            ('user8', generate_password_hash('456789'), 'user'),
            ('user9', generate_password_hash('456789'), 'user'),
            ('user10', generate_password_hash('456789'), 'user'),
            ('user11', generate_password_hash('456789'), 'user'),
            ('user12', generate_password_hash('456789'), 'user'),
            ('user13', generate_password_hash('456789'), 'user'),
            ('user14', generate_password_hash('456789'), 'user'),
            ('user15', generate_password_hash('456789'), 'user'),
            ('user16', generate_password_hash('456789'), 'user'),
            ('user17', generate_password_hash('456789'), 'user'),
            ('user18', generate_password_hash('456789'), 'user'),
            ('user19', generate_password_hash('456789'), 'user'),
            ('user20', generate_password_hash('456789'), 'user')
        ]
        c.executemany('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''', user_users)

    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username, role FROM users')
    users = c.fetchall()
    conn.close()

    return render_template('main.html', username=session['username'], users=users)

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
            session['role'] = user[3]

            if user[3] == 'admin':
                return redirect(url_for('admin'))
            elif user[3] == 'superadmin':
                return redirect(url_for('superadmin'))
            elif user[3] == 'user':
                return redirect(url_for('home'))
        else:
            return "Invalid credentials. Please try again."

    return render_template('login.html')

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

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username, role FROM users')
    users = c.fetchall()
    if session['role']== 'admin':
        return render_template('admin.html',users=users)   
    if session['role']== 'superadmin':
        return render_template('superadmin.html',users=users) 
    else:
        return render_template('main.html',users=users) 


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))
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
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, role, blocked FROM users WHERE role IN ("user", "admin")')
    users = c.fetchall()
    conn.close()

    return render_template('admin.html',users=users)

@app.route('/superadmin')
def superadmin():
    if 'username' not in session or session['role'] != 'superadmin':
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, role, blocked FROM users')
    users = c.fetchall()
    conn.close()

    return render_template('superadmin.html', users=users)

@app.route('/change_role/<int:user_id>/<new_role>')
def change_role(user_id, new_role):
    if 'username' not in session or session['role'] != 'superadmin':
        return redirect(url_for('login'))
    
    if new_role not in ['user', 'admin', 'superadmin']:
        return "Invalid role", 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('superadmin'))



@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Ensure the current user is logged in and has the superadmin role
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('superadmin'))

# @app.route('/block_user/<int:user_id>')
# def block_user(user_id):
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('UPDATE users SET blocked = 1 WHERE id = ?', (user_id,))
#     conn.commit()
#     conn.close()
#     return redirect(url_for('superadmin'))

# @app.route('/unblock_user/<int:user_id>')
# def unblock_user(user_id):
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('UPDATE users SET blocked = 0 WHERE id = ?', (user_id,))
#     conn.commit()
#     conn.close()
#     return redirect(url_for('superadmin'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=9500)























































































# from flask import Flask, render_template, request, url_for, redirect, session
# import sqlite3
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = 'racecar'

# # Initialize the database and create the 'users' table
# def init_db():
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users
#               (id INTEGER PRIMARY KEY, username TEXT,
#                password TEXT, role TEXT DEFAULT 'user', blocked INTEGER DEFAULT 0)''')
    
#     # Check if a superadmin exists, if not, create one
#     c.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
#     superadmin_count = c.fetchone()[0]
#     c.execute('''SELECT COUNT(*) FROM users WHERE role = "admin"''')
#     admin_count = c.fetchone()[0]
    
#     if superadmin_count == 0:
#         c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
#               ('maxin', generate_password_hash('matrix@60'), 'superadmin'))
    
#     if admin_count == 0:
#         c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
#               ('hill', generate_password_hash('123456'), 'admin'))

#     conn.commit()
#     conn.close()

# # Home route (user page)
# @app.route('/')
# def home():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     # Get all users and their roles
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('SELECT username, role FROM users')
#     users = c.fetchall()
#     conn.close()

#     return render_template('main.html', username=session['username'], users=users)

# # Signup route
# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         hashed_password = generate_password_hash(password)

#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('INSERT INTO users(username, password) VALUES(?, ?)', (username, hashed_password))
#         conn.commit()
#         conn.close()
#         return redirect(url_for('login'))
#     return render_template('signup.html')

# # Login route
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         # Connect to the database
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT * FROM users WHERE username = ?', (username,))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[2], password):
#             session['username'] = username
#             session['role'] = user[3]

#             if user[3] == 'admin':
#                 return redirect(url_for('admin'))
#             elif user[3] == 'superadmin':
#                 return redirect(url_for('superadmin'))
#             elif user[3] == 'user':
#                 return redirect(url_for('home'))  # Redirect to the home page for a regular user
#         else:
#             return "Invalid credentials. Please try again."

#     return render_template('login.html')

# # Logout route
# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('login'))

# # Admin route
# @app.route('/admin')
# def admin():
#     if 'username' not in session or session['role'] != 'admin':
#         return redirect(url_for('login'))
    
#     return render_template('admin.html')

# # Superadmin route
# @app.route('/superadmin')
# def superadmin():
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     # Retrieve all users and their roles
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('SELECT id, username, role, blocked FROM users')
#     users = c.fetchall()
#     conn.close()

#     return render_template('superadmin.html', users=users)

# # Change role route
# @app.route('/change_role/<int:user_id>/<new_role>')
# def change_role(user_id, new_role):
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))
    
#     if new_role not in ['user', 'admin', 'superadmin']:
#         return "Invalid role", 400

#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
#     conn.commit()
#     conn.close()
    
#     return redirect(url_for('superadmin'))

# # Block user
# @app.route('/block_user/<int:user_id>')
# def block_user(user_id):
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('UPDATE users SET blocked = 1 WHERE id = ?', (user_id,))
#     conn.commit()
#     conn.close()
#     return redirect(url_for('superadmin'))

# # Unblock user
# @app.route('/unblock_user/<int:user_id>')
# def unblock_user(user_id):
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('UPDATE users SET blocked = 0 WHERE id = ?', (user_id,))
#     conn.commit()
#     conn.close()
#     return redirect(url_for('superadmin'))

# if __name__ == "__main__":
#     init_db()
#     app.run(debug=True, port=9500)















































































































































# # # from flask import Flask, render_template, request, url_for, redirect, session
# # # import sqlite3
# # # from werkzeug.security import generate_password_hash, check_password_hash

# # # app = Flask(__name__)
# # # app.secret_key = 'racecar'

# # # # Initialize the database and create the 'users' table
# # # def init_db():
# # #     conn = sqlite3.connect('users.db')
# # #     c = conn.cursor()
# # #     c.execute(''' CREATE TABLE IF NOT EXISTS users
# # #               (id INTEGER PRIMARY KEY, username TEXT,
# # #                password TEXT, role TEXT DEFAULT 'user')''')
    
# # #     # Check if a superadmin exists, if not, create one
# # #     c.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
# # #     if c.fetchone()[0] == 0:
# # #         c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
# # #                   ('maxin', generate_password_hash('matrix@60'), 'superadmin'))
# # #     conn.commit()
# # #     conn.close()

# # # @app.route('/')
# # # def home():
# # #     if 'username' in session:
# # #         return render_template('main.html', username=session['username'])
# # #     return redirect(url_for('login'))

# # # @app.route('/signup', methods=['GET', 'POST'])
# # # def signup():
# # #     if request.method == 'POST':
# # #         username = request.form['username']
# # #         password = request.form['password']
# # #         hashed_password = generate_password_hash(password)

# # #         conn = sqlite3.connect('users.db')
# # #         c = conn.cursor()
# # #         c.execute('INSERT INTO users(username, password) VALUES(?, ?)', (username, hashed_password))
# # #         conn.commit()
# # #         conn.close()
# # #         return redirect(url_for('login'))
# # #     return render_template('signup.html')

# # # @app.route('/login', methods=['GET', 'POST'])
# # # def login():
# # #     if request.method == 'POST':
# # #         username = request.form['username']
# # #         password = request.form['password']

# # #         conn = sqlite3.connect('users.db')
# # #         c = conn.cursor()
# # #         c.execute('SELECT * FROM users WHERE username = ?', (username,))
# # #         user = c.fetchone()
# # #         conn.close()

# # #         if user and check_password_hash(user[2], password):
# # #             session['username'] = username
# # #             role = user[3]
# # #             if role == 'admin':
# # #                 return redirect(url_for('admin'))
# # #             elif role == 'user':
# # #                 return redirect(url_for('home'))
# # #             elif role == 'superadmin':
# # #                 return redirect(url_for('superadmin'))
# # #         return "Invalid credentials. Please try again."
    
# # #     return render_template('login.html')

# # # @app.route('/logout')
# # # def logout():
# # #     session.pop('username', None)
# # #     return redirect(url_for('login'))

# @app.route('/update_password', methods=['POST', 'GET'])
# def update_password():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         current_password = request.form['current_password']
#         new_password = request.form['new_password']
#         hashed_new_password = generate_password_hash(new_password)

#         # Verify the current password
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[0], current_password):
#             # Update the password if the current password is correct
#             conn = sqlite3.connect('users.db')
#             c = conn.cursor()
#             c.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_new_password, session['username']))
#             conn.commit()
#             conn.close()
#             return redirect(url_for('home'))
#         else:
#             return "Incorrect current password. Please try again."

#     return render_template('update_password.html')

# @app.route('/delete_account', methods=['GET', 'POST'])
# def delete_account():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         current_password = request.form['current_password']

#         # Verify the current password
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[0], current_password):
#             # Delete the account if the current password is correct
#             conn = sqlite3.connect('users.db')
#             c = conn.cursor()
#             c.execute('DELETE FROM users WHERE username = ?', (session['username'],))
#             conn.commit()
#             conn.close()
#             session.pop('username', None)
#             return redirect(url_for('login'))
#         else:
#             return "Incorrect password. Please try again."

#     return render_template('delete_account.html')

# # # @app.route('/admin')
# # # def admin():
# # #     if 'username' not in session:
# # #         return redirect(url_for('login'))
    
# # #     if session['username'] != 'admin':
# # #         return redirect(url_for('home'))
    
# # #     return render_template('admin.html')

# # # @app.route('/superadmin')
# # # def superadmin():
# # #     if 'username' not in session:
# # #         return redirect(url_for('login'))
    
# # #     if session['username'] != 'superadmin':
# # #         return redirect(url_for('home'))
    
# # #     conn = sqlite3.connect('users.db')
# # #     c = conn.cursor()
# # #     c.execute('SELECT id, username, role FROM users')
# # #     users = c.fetchall()
# # #     conn.close()
    
# # #     return render_template('superadmin.html', users=users)

# # # @app.route('/change_role/<int:user_id>/<new_role>')
# # # def change_role(user_id, new_role):
# # #     if 'username' not in session or session['username'] != 'superadmin':
# # #         return redirect(url_for('login'))
    
# # #     if new_role not in ['user', 'admin', 'superadmin']:
# # #         return "Invalid role", 400

# # #     conn = sqlite3.connect('users.db')
# # #     c = conn.cursor()
# # #     c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
# # #     conn.commit()
# # #     conn.close()
    
# # #     return redirect(url_for('superadmin'))

# # # if __name__ == "__main__":
# # #     init_db()
# # #     app.run(debug=True,port= 8000)




# # from flask import Flask, render_template, request, url_for, redirect, session
# # import sqlite3
# # from werkzeug.security import generate_password_hash, check_password_hash

# # app = Flask(__name__)
# # app.secret_key = 'racecar'

# # def init_db():
# #     conn = sqlite3.connect('users.db')
# #     c = conn.cursor()
# #     c.execute('''CREATE TABLE IF NOT EXISTS users
# #               (id INTEGER PRIMARY KEY, username TEXT,
# #                password TEXT, role TEXT DEFAULT 'user')''')
# #     c.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
# #     superadmin_count = c.fetchone()[0]
# #     c.execute('''SELECT COUNT(*) FROM users WHERE role = "admin"''')
# #     admin_count = c.fetchone()[0]

# # # If no superadmin exists, insert one
# #     if superadmin_count == 0:
# #         c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
# #               ('maxin', generate_password_hash('matrix@60'), 'superadmin'))

# # # If no admin exists, insert one
# #     if admin_count == 0:
# #         c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
# #               ('hill', generate_password_hash('123456'), 'admin'))

# #     conn.commit()
# #     conn.close()

# # # @app.route('/')
# # # def home():
# # #     if 'username' in session:
# # #         return render_template('main.html', username=session['username'])
# # #     return redirect(url_for('login'))

# # @app.route('/home')
# # def home():
# #     if 'username' not in session:
# #         return redirect(url_for('login'))
    
# #     # Get all users and their roles
# #     conn = sqlite3.connect('users.db')
# #     c = conn.cursor()
# #     c.execute('SELECT username, role FROM users')
# #     users = c.fetchall()
# #     conn.close()

# #     return render_template('main.html', username=session['username'], users=users)


# # @app.route('/signup', methods=['GET', 'POST'])
# # def signup():
# #     if request.method == 'POST':
# #         username = request.form['username']
# #         password = request.form['password']
# #         hashed_password = generate_password_hash(password)

# #         conn = sqlite3.connect('users.db')
# #         c = conn.cursor()
# #         c.execute('INSERT INTO users(username, password) VALUES(?, ?)', (username, hashed_password))
# #         conn.commit()
# #         conn.close()
# #         return redirect(url_for('login'))
# #     return render_template('signup.html')

# # @app.route('/login', methods=['GET', 'POST'])
# # def login():
# #     if request.method == 'POST':
# #         username = request.form['username']
# #         password = request.form['password']

# #         conn = sqlite3.connect('users.db')
# #         c = conn.cursor()
# #         c.execute('SELECT * FROM users WHERE username = ?', (username,))
# #         user = c.fetchone()
# #         conn.close()

# #         if user and check_password_hash(user[2], password):
# #             session['username'] = username
# #             role = user[3]
# #             if role == 'admin':
# #                 return redirect(url_for('admin'))
# #             elif role == 'user':
# #                 return redirect(url_for('home'))
# #             elif role == 'superadmin':
# #                 return redirect(url_for('superadmin'))
# #         return "Invalid credentials. Please try again."
    
# #     return render_template('login.html')

# # @app.route('/logout')
# # def logout():
# #     session.pop('username', None)
# #     return redirect(url_for('login'))

# # @app.route('/update_password', methods=['POST', 'GET'])
# # def update_password():
# #     if 'username' not in session:
# #         return redirect(url_for('login'))

# #     if request.method == 'POST':
# #         current_password = request.form['current_password']
# #         new_password = request.form['new_password']
# #         hashed_new_password = generate_password_hash(new_password)

# #         # Verify the current password
# #         conn = sqlite3.connect('users.db')
# #         c = conn.cursor()
# #         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
# #         user = c.fetchone()
# #         conn.close()

# #         if user and check_password_hash(user[0], current_password):
# #             # Update the password if the current password is correct
# #             conn = sqlite3.connect('users.db')
# #             c = conn.cursor()
# #             c.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_new_password, session['username']))
# #             conn.commit()
# #             conn.close()
# #             return redirect(url_for('home'))
# #         else:
# #             return "Incorrect current password. Please try again."

# #     return render_template('update_password.html')

# # @app.route('/delete_account', methods=['GET', 'POST'])
# # def delete_account():
# #     if 'username' not in session:
# #         return redirect(url_for('login'))

# #     if request.method == 'POST':
# #         current_password = request.form['current_password']

# #         # Verify the current password
# #         conn = sqlite3.connect('users.db')
# #         c = conn.cursor()
# #         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
# #         user = c.fetchone()
# #         conn.close()

# #         if user and check_password_hash(user[0], current_password):
# #             # Delete the account if the current password is correct
# #             conn = sqlite3.connect('users.db')
# #             c = conn.cursor()
# #             c.execute('DELETE FROM users WHERE username = ?', (session['username'],))
# #             conn.commit()
# #             conn.close()
# #             session.pop('username', None)
# #             return redirect(url_for('login'))
# #         else:
# #             return "Incorrect password. Please try again."

# #     return render_template('delete_account.html')

# # @app.route('/admin')
# # def admin():
# #     if 'username' not in session or session['username'] != 'admin':
# #         return redirect(url_for('login'))

# #     return render_template('admin.html')

# # # @app.route('/superadmin')
# # # def superadmin():
# # #     if 'username' not in session:
# # #         return redirect(url_for('login'))
    
# # #     if session['username'] != 'superadmin':
# # #         return redirect(url_for('home'))
    
# # #     conn = sqlite3.connect('users.db')
# # #     c = conn.cursor()
# # #     c.execute('SELECT id, username, role FROM users')
# # #     users = c.fetchall()
# # #     conn.close()
    
# # #     return render_template('superadmin.html', users=users)

# # @app.route('/superadmin')
# # def superadmin():
# #     if 'username' not in session:
# #         return redirect(url_for('login'))

# #     if session['username'] != 'superadmin':
# #         return redirect(url_for('home'))

# #     # Retrieve all users and their roles
# #     conn = sqlite3.connect('users.db')
# #     c = conn.cursor()
# #     c.execute('SELECT id, username, role FROM users')
# #     users = c.fetchall()
# #     conn.close()

# #     return render_template('superadmin.html', users=users)

# # @app.route('/change_role/<int:user_id>/<new_role>')
# # def change_role(user_id, new_role):
# #     if 'username' not in session or session['username'] != 'superadmin':
# #         return redirect(url_for('login'))
    
# #     if new_role not in ['user', 'admin', 'superadmin']:
# #         return "Invalid role", 400

# #     conn = sqlite3.connect('users.db')
# #     c = conn.cursor()
# #     c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
# #     conn.commit()
# #     conn.close()
    
# #     return redirect(url_for('superadmin'))

# # if __name__ == "__main__":
# #     init_db()
# #     app.run(debug=True,port=9500)



# from flask import Flask, render_template, request, url_for, redirect, session
# import sqlite3
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = 'racecar'

# # Initialize the database and create the 'users' table
# def init_db():
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users
#               (id INTEGER PRIMARY KEY, username TEXT,
#                password TEXT, role TEXT DEFAULT 'user')''')
    
#     # Check if a superadmin exists, if not, create one
#     c.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
#     superadmin_count = c.fetchone()[0]
#     c.execute('''SELECT COUNT(*) FROM users WHERE role = "admin"''')
#     admin_count = c.fetchone()[0]
    
#     if superadmin_count == 0:
#         c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
#               ('maxin', generate_password_hash('matrix@60'), 'superadmin'))
    
    # if admin_count == 0:
    #     c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
    #           ('hill', generate_password_hash('123456'), 'admin'))

#     conn.commit()
#     conn.close()

# # Home route (user page)
# @app.route('/')
# def home():

#     if 'username' not in session:
#         return redirect(url_for('login'))

#     # Get all users and their roles
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('SELECT username, role FROM users')
#     users = c.fetchall()
#     conn.close()

#     return render_template('main.html', username=session['username'], users=users)

# # Signup route
# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         hashed_password = generate_password_hash(password)

#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('INSERT INTO users(username, password) VALUES(?, ?)', (username, hashed_password))
#         conn.commit()
#         conn.close()
#         return redirect(url_for('login'))
#     return render_template('signup.html')

# # # Login route
# # @app.route('/login', methods=['GET', 'POST'])
# # def login():
# #     if request.method == 'POST':
# #         username = request.form['username']
# #         password = request.form['password']

# #         conn = sqlite3.connect('users.db')
# #         c = conn.cursor()
# #         c.execute('SELECT * FROM users WHERE username = ?', (username,))
# #         user = c.fetchone()
# #         conn.close()

# #         if user and check_password_hash(user[2], password):
# #             session['username'] = username
# #             role = user[3]
# #             if role[3] == 'admin':
# #                 return redirect(url_for('admin'))
# #             elif role[3] == 'user':
# #                 return redirect(url_for('home'))
# #             elif role[3] == 'superadmin':
# #                 return redirect(url_for('superadmin'))
# #             return "Invalid credentials. Please try again."
    
# #     return render_template('login.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         # Connect to the database
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT * FROM users WHERE username = ?', (username,))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[2], password):
#             # Setting session variables
#             session['username'] = username
#             session['role'] = user[3]  # Store the role in session as well
            
            
#             # Redirect based on user role
#             if user[3] == 'admin':
#                 return redirect(url_for('admin'))
#             elif user[3] == 'superadmin':
#                 return redirect(url_for('superadmin'))
#             elif user[3] == 'user':
#                 return redirect(url_for('home'))
#         else:
#             return "Invalid credentials. Please try again."
    
#     return render_template('login.html')



# # Logout route
# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('login'))

# # Password update route
# @app.route('/update_password', methods=['POST', 'GET'])
# def update_password():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         current_password = request.form['current_password']
#         new_password = request.form['new_password']
#         hashed_new_password = generate_password_hash(new_password)

#         # Verify the current password
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[0], current_password):
#             # Update the password if the current password is correct
#             conn = sqlite3.connect('users.db')
#             c = conn.cursor()
#             c.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_new_password, session['username']))
#             conn.commit()
#             conn.close()
#             return redirect(url_for('home'))
#         else:
#             return "Incorrect current password. Please try again."

#     return render_template('update_password.html')

# # Delete account route
# @app.route('/delete_account', methods=['GET', 'POST'])
# def delete_account():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         current_password = request.form['current_password']

#         # Verify the current password
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[0], current_password):
#             # Delete the account if the current password is correct
#             conn = sqlite3.connect('users.db')
#             c = conn.cursor()
#             c.execute('DELETE FROM users WHERE username = ?', (session['username'],))
#             conn.commit()
#             conn.close()
#             session.pop('username', None)
#             return redirect(url_for('login'))
#         else:
#             return "Incorrect password. Please try again."

#     return render_template('delete_account.html')

# # Admin route
# @app.route('/admin')
# def admin():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     if session['username'] != 'admin':
#         return redirect(url_for('home'))
    
#     return render_template('admin.html')

# # Superadmin route
# @app.route('/superadmin')
# def superadmin():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     if session['username'] != 'superadmin':
#         return redirect(url_for('home'))

#     # Retrieve all users and their roles
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('SELECT id, username, role FROM users')
#     users = c.fetchall()
#     conn.close()

#     return render_template('superadmin.html', users=users)

# # Change role route
# @app.route('/change_role/<int:user_id>/<new_role>')
# def change_role(user_id, new_role):
#     if 'username' not in session or session['username'] != 'superadmin':
#         return redirect(url_for('login'))
    
#     if new_role not in ['user', 'admin', 'superadmin']:
#         return "Invalid role", 400

#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
#     conn.commit()
#     conn.close()
    
#     return redirect(url_for('superadmin'))

# if __name__ == "__main__":
#     init_db()
#     app.run(debug=True, port=9500)
