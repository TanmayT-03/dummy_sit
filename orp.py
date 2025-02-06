from flask import Flask, render_template, request, url_for, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)
app.secret_key = 'racecar'

# Configure MySQL
app.config['MYSQL_HOST'] = 'localhost'  # Change to your MySQL server
app.config['MYSQL_USER'] = 'root'       # MySQL user
app.config['MYSQL_PASSWORD'] = 'admin'  # MySQL password
app.config['MYSQL_DB'] = 'flaskapp'     # MySQL database



def init_db():
   
    try:
        # Establish the connection
        conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        
        # Check if the connection was successful
        if conn.is_connected():
            print("Connected to MySQL server")

            cursor = conn.cursor()
            # Create users table if it doesn't exist
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INT AUTO_INCREMENT PRIMARY KEY, 
                                username VARCHAR(100), 
                                password TEXT, 
                                role VARCHAR(20) DEFAULT 'user')''')

            cursor.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
            superadmin_count = cursor.fetchone()[0]
            cursor.execute('''SELECT COUNT(*) FROM users WHERE role = "admin"''')
            admin_count = cursor.fetchone()[0]

            if superadmin_count == 0:
                cursor.execute('''INSERT INTO users(username, password, role) VALUES (%s, %s, %s)''',
                               ('maxin', generate_password_hash('matrix@60'), 'superadmin'))

            if admin_count == 0:
                admin_users = [
                    ('hill', generate_password_hash('789456'), 'admin'),
                    ('admin2', generate_password_hash('123456'), 'admin'),
                    ('admin3', generate_password_hash('123456'), 'admin'),
                    ('admin4', generate_password_hash('123456'), 'admin'),
                    ('admin5', generate_password_hash('123456'), 'admin')
                ]
                cursor.executemany('''INSERT INTO users(username, password, role) VALUES (%s, %s, %s)''', admin_users)

            # Add some user data
            cursor.execute("SELECT role FROM users WHERE role = 'user'")
            user_count = len(cursor.fetchall())
            if user_count == 0:
                user_users = [
                    ('user1', generate_password_hash('456789'), 'user'),
                    ('user2', generate_password_hash('456789'), 'user'),
                    ('user3', generate_password_hash('456789'), 'user'),
                    ('user4', generate_password_hash('456789'), 'user'),
                    ('user5', generate_password_hash('456789'), 'user')
                ]
                cursor.executemany('''INSERT INTO users(username, password, role) VALUES (%s, %s, %s)''', user_users)

            conn.commit()
            print("Database initialized successfully.")
        else:
            print("Failed to connect to MySQL server.")
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        # Ensure that the connection is closed if it was successfully opened
        if conn.is_connected():
            cursor.close()
            conn.close()
            print("Connection closed.")

# # Initialize DB
# def init_db():
#     try:
#         conn = mysql.connector.connect(
#             host=app.config['MYSQL_HOST'],
#             user=app.config['MYSQL_USER'],
#             password=app.config['MYSQL_PASSWORD'],
#             database=app.config['MYSQL_DB']
#         )

#         cursor = conn.cursor()

#         # Create users table if it doesn't exist
#         cursor.execute('''CREATE TABLE IF NOT EXISTS users (
#                             id INT AUTO_INCREMENT PRIMARY KEY, 
#                             username VARCHAR(100), 
#                             password TEXT, 
#                             role VARCHAR(20) DEFAULT 'user')''')

#         cursor.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
#         superadmin_count = cursor.fetchone()[0]
#         cursor.execute('''SELECT COUNT(*) FROM users WHERE role = "admin"''')
#         admin_count = cursor.fetchone()[0]

#         if superadmin_count == 0:
#             cursor.execute('''INSERT INTO users(username, password, role) VALUES (%s, %s, %s)''',
#                            ('maxin', generate_password_hash('matrix@60'), 'superadmin'))

#         if admin_count == 0:
#             admin_users = [
#                 ('hill', generate_password_hash('789456'), 'admin'),
#                 ('admin2', generate_password_hash('123456'), 'admin'),
#                 ('admin3', generate_password_hash('123456'), 'admin'),
#                 ('admin4', generate_password_hash('123456'), 'admin'),
#                 ('admin5', generate_password_hash('123456'), 'admin')
#             ]
#             cursor.executemany('''INSERT INTO users(username, password, role) VALUES (%s, %s, %s)''', admin_users)

#         # Add some user data
#         cursor.execute("SELECT role FROM users WHERE role = 'user'")
#         user_count = len(cursor.fetchall())
#         if user_count == 0:
#             user_users = [
#                 ('user1', generate_password_hash('456789'), 'user'),
#                 ('user2', generate_password_hash('456789'), 'user'),
#                 ('user3', generate_password_hash('456789'), 'user'),
#                 ('user4', generate_password_hash('456789'), 'user'),
#                 ('user5', generate_password_hash('456789'), 'user')
#             ]
#             cursor.executemany('''INSERT INTO users(username, password, role) VALUES (%s, %s, %s)''', user_users)

#         conn.commit()
#     except Error as e:
#         print(f"Error: {e}")
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        cursor = conn.cursor()
        cursor.execute('SELECT username, role FROM users')
        users = cursor.fetchall()
        conn.close()
        return render_template('main.html', username=session['username'], users=users)

    except Error as e:
        print(f"Error: {e}")
        return "Database connection error."

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        try:
            conn = mysql.connector.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                password=app.config['MYSQL_PASSWORD'],
                database=app.config['MYSQL_DB']
            )
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users(username, password) VALUES(%s, %s)', (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))

        except Error as e:
            print(f"Error: {e}")
            return "Database connection error."

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = mysql.connector.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                password=app.config['MYSQL_PASSWORD'],
                database=app.config['MYSQL_DB']
            )
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
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

        except Error as e:
            print(f"Error: {e}")
            return "Database connection error."

    return render_template('login.html')

@app.route('/update_password', methods=['POST', 'GET'])
def update_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        hashed_new_password = generate_password_hash(new_password)

        try:
            conn = mysql.connector.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                password=app.config['MYSQL_PASSWORD'],
                database=app.config['MYSQL_DB']
            )
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE username = %s', (session['username'],))
            user = cursor.fetchone()
            conn.close()

            if user and check_password_hash(user[0], current_password):
                # Update the password if the current password is correct
                conn = mysql.connector.connect(
                    host=app.config['MYSQL_HOST'],
                    user=app.config['MYSQL_USER'],
                    password=app.config['MYSQL_PASSWORD'],
                    database=app.config['MYSQL_DB']
                )
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password = %s WHERE username = %s', (hashed_new_password, session['username']))
                conn.commit()
                conn.close()
                return redirect(url_for('home'))
            else:
                return "Incorrect current password. Please try again."

        except Error as e:
            print(f"Error: {e}")
            return "Database connection error."

    return render_template('update_password.html')

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']

        try:
            conn = mysql.connector.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                password=app.config['MYSQL_PASSWORD'],
                database=app.config['MYSQL_DB']
            )
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE username = %s', (session['username'],))
            user = cursor.fetchone()
            conn.close()

            if user and check_password_hash(user[0], current_password):
                # Delete the account if the current password is correct
                conn = mysql.connector.connect(
                    host=app.config['MYSQL_HOST'],
                    user=app.config['MYSQL_USER'],
                    password=app.config['MYSQL_PASSWORD'],
                    database=app.config['MYSQL_DB']
                )
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE username = %s', (session['username'],))
                conn.commit()
                conn.close()
                session.pop('username', None)
                return redirect(url_for('login'))
            else:
                return "Incorrect password. Please try again."

        except Error as e:
            print(f"Error: {e}")
            return "Database connection error."

    return render_template('delete_account.html')

@app.route('/admin')
def admin():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    try:
        conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, blocked FROM users WHERE role IN ("user", "admin")')
        users = cursor.fetchall()
        conn.close()

        return render_template('admin.html', users=users)

    except Error as e:
        print(f"Error: {e}")
        return "Database connection error."

@app.route('/superadmin')
def superadmin():
    if 'username' not in session or session['role'] != 'superadmin':
        return redirect(url_for('login'))

    try:
        conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, blocked FROM users')
        users = cursor.fetchall()
        conn.close()

        return render_template('superadmin.html', users=users)

    except Error as e:
        print(f"Error: {e}")
        return "Database connection error."

@app.route('/change_role/<int:user_id>/<new_role>', methods=['GET'])
def change_role(user_id, new_role):
    if 'username' not in session or session['role'] != 'superadmin':
        return redirect(url_for('login'))

    if new_role not in ['user', 'admin', 'superadmin']:
        return jsonify({"error": "Invalid role"}), 400

    try:
        conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET role = %s WHERE id = %s', (new_role, user_id))
        conn.commit()
        conn.close()

        return jsonify({"message": f"Role changed to {new_role} for user {user_id}"}), 200

    except Error as e:
        print(f"Error: {e}")
        return jsonify({"error": "Database error"}), 500

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' not in session or session['role'] != 'superadmin':
        return redirect(url_for('login'))

    try:
        conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        conn.close()

        return redirect(url_for('superadmin'))

    except Error as e:
        print(f"Error: {e}")
        return "Database connection error."

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=9500)































































# from flask import Flask, render_template, request, url_for, redirect, session, jsonify
# from werkzeug.security import generate_password_hash, check_password_hash
# from flask_mysqldb import MySQL

# app = Flask(__name__)
# app.secret_key = 'racecar'

# # Configure MySQL
# app.config['MYSQL_HOST'] = 'localhost'  # Change to your MySQL server
# app.config['MYSQL_USER'] = 'root'       # MySQL user
# app.config['MYSQL_PASSWORD'] = 'password'  # MySQL password
# app.config['MYSQL_DB'] = 'flaskapp'     # MySQL database

# mysql = MySQL(app)

# # Initialize DB
# def init_db():
#     conn = mysql.connect
#     c = conn.cursor()
    
#     # Create users table if it doesn't exist
#     c.execute('''CREATE TABLE IF NOT EXISTS users (
#                     id INT AUTO_INCREMENT PRIMARY KEY, 
#                     username VARCHAR(100), 
#                     password TEXT, 
#                     role VARCHAR(20) DEFAULT 'user')''')
    
#     c.execute('''SELECT COUNT(*) FROM users WHERE role = "superadmin"''')
#     superadmin_count = c.fetchone()[0]
#     c.execute('''SELECT COUNT(*) FROM users WHERE role = "admin"''')
#     admin_count = c.fetchone()[0]

#     if superadmin_count == 0:
#         c.execute('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''',
#                   ('maxin', generate_password_hash('matrix@60'), 'superadmin'))
    
#     if admin_count == 0:
#         admin_users = [
#             ('hill', generate_password_hash('789456'), 'admin'),
#             ('admin2', generate_password_hash('123456'), 'admin'),
#             ('admin3', generate_password_hash('123456'), 'admin'),
#             ('admin4', generate_password_hash('123456'), 'admin'),
#             ('admin5', generate_password_hash('123456'), 'admin')
#         ]
#         c.executemany('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''', admin_users)
    
#     # Add some user data
#     user_count = len([1 for user in c.execute("SELECT role FROM users WHERE role = 'user'")])
#     if user_count == 0:
#         user_users = [
#             ('user1', generate_password_hash('456789'), 'user'),
#             ('user2', generate_password_hash('456789'), 'user'),
#             ('user3', generate_password_hash('456789'), 'user'),
#             ('user4', generate_password_hash('456789'), 'user'),
#             ('user5', generate_password_hash('456789'), 'user')
#         ]
#         c.executemany('''INSERT INTO users(username, password, role) VALUES (?, ?, ?)''', user_users)

#     conn.commit()
#     conn.close()

# @app.route('/')
# def home():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     conn = mysql.connect
#     c = conn.cursor()
#     c.execute('SELECT username, role FROM users')
#     users = c.fetchall()
#     conn.close()

#     return render_template('main.html', username=session['username'], users=users)

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         hashed_password = generate_password_hash(password)

#         conn = mysql.connect
#         c = conn.cursor()
#         c.execute('INSERT INTO users(username, password) VALUES(?, ?)', (username, hashed_password))
#         conn.commit()
#         conn.close()
#         return redirect(url_for('login'))
#     return render_template('signup.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         conn = mysql.connect
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
#                 return redirect(url_for('home'))
#         else:
#             return "Invalid credentials. Please try again."

#     return render_template('login.html')

# @app.route('/update_password', methods=['POST', 'GET'])
# def update_password():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         current_password = request.form['current_password']
#         new_password = request.form['new_password']
#         hashed_new_password = generate_password_hash(new_password)

#         # Verify the current password
#         conn = mysql.connect
#         c = conn.cursor()
#         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[0], current_password):
#             # Update the password if the current password is correct
#             conn = mysql.connect
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
#         conn = mysql.connect
#         c = conn.cursor()
#         c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[0], current_password):
#             # Delete the account if the current password is correct
#             conn = mysql.connect
#             c = conn.cursor()
#             c.execute('DELETE FROM users WHERE username = ?', (session['username'],))
#             conn.commit()
#             conn.close()
#             session.pop('username', None)
#             return redirect(url_for('login'))
#         else:
#             return "Incorrect password. Please try again."

#     return render_template('delete_account.html')

# @app.route('/admin')
# def admin():
#     if 'username' not in session or session['role'] != 'admin':
#         return redirect(url_for('login'))

#     conn = mysql.connect
#     c = conn.cursor()
#     c.execute('SELECT id, username, role, blocked FROM users WHERE role IN ("user", "admin")')
#     users = c.fetchall()
#     conn.close()

#     return render_template('admin.html', users=users)

# @app.route('/superadmin')
# def superadmin():
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     conn = mysql.connect
#     c = conn.cursor()
#     c.execute('SELECT id, username, role, blocked FROM users')
#     users = c.fetchall()
#     conn.close()

#     return render_template('superadmin.html', users=users)

# @app.route('/change_role/<int:user_id>/<new_role>', methods=['GET'])
# def change_role(user_id, new_role):
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     if new_role not in ['user', 'admin', 'superadmin']:
#         return jsonify({"error": "Invalid role"}), 400

#     conn = mysql.connect
#     c = conn.cursor()
#     c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
#     conn.commit()
#     conn.close()

#     return jsonify({"message": f"Role changed to {new_role} for user {user_id}"}), 200


# @app.route('/delete_user/<int:user_id>', methods=['POST'])
# def delete_user(user_id):
#     if 'username' not in session or session['role'] != 'superadmin':
#         return redirect(url_for('login'))

#     conn = mysql.connect
#     c = conn.cursor()
#     c.execute('DELETE FROM users WHERE id = ?', (user_id,))
#     conn.commit()
#     conn.close()

#     return redirect(url_for('superadmin'))

# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('login'))

# if __name__ == "__main__":
#     init_db()
#     app.run(debug=True, port=9500)
