from flask import Flask, render_template, request, redirect, url_for, session
import bcrypt
import pyotp

app = Flask(__name__)
app.secret_key = 'yahyasafi' 

users = {}

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password(user['password'], password):
            session['username'] = username
            return redirect(url_for('two_factor'))
        else:
            return "Invalid username or password."
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return "User already exists!"
        hashed_password = hash_password(password)
        secret = pyotp.random_base32()
        users[username] = {'password': hashed_password, 'secret': secret}
        return render_template('show_secret.html', secret=secret)
    return render_template('register.html')


@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    if request.method == 'POST':
        token = request.form['token']
        totp = pyotp.TOTP(users[username]['secret'])
        if totp.verify(token):
            return f"Welcome, {username}!"
        else:
            return "Invalid 2FA token."
    return render_template('two_factor.html')

if __name__ == '__main__':
    app.run(debug=True)
