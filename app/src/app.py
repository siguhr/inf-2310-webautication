from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path
import ssl
import bcrypt
import OpenSSL

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask app
app = Flask(__name__)
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

# Define constants
PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = ":"

# Create a password file if it doesn't exist
if not os.path.exists(PASSWORDFILE):
    open(PASSWORDFILE, 'w').close()

# Define rate limiting and IP blocking
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["3 per hour"])




# Define the route for the home page
@app.route('/')
@limiter.limit("5 per minute")
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return render_template('home.html')

# Define the route for the registration page
@app.route('/register', methods=['GET'])
@limiter.limit("5 per minute")
def register_get():
    return render_template('register.html')

# Define the route for submitting the registration form
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_post():
    # Get the username and password from the registration form
    username = request.form['username']
    password = request.form['password']

    # If the username or password is empty, flash an error message and redirect back to the registration page
    if not username or not password:
        flash('Please enter a username and password.')
        return redirect(url_for('register_get'))
    
    # Hash the password and write it to the password file
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open(PASSWORDFILE, 'a') as f:
        f.write(f'{username}{PASSWORDFILEDELIMITER}{hashed_password.decode("utf-8")}\n')

    # Flash a success message and redirect to the login page
    flash('Registration successful! Please log in.')
    return redirect(url_for('login_get'))

# Define the route for the login page
@app.route('/login', methods=['GET'])
@limiter.limit("5 per minute")
def login_get():
    return render_template('login.html')


# Define the route for submitting the login form
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login_post():
    username = request.form['username']
    password = request.form['password']

    # Check if the username and password match a record in the password file
    with open(PASSWORDFILE, 'r') as f:
        for line in f:
            stored_username, stored_password = line.strip().split(PASSWORDFILEDELIMITER)
            if username == stored_username and bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):

                # If the username and password match, store the username in the session and redirect to the logged-in page
                session['username'] = username
                return redirect(url_for('loggedin'))
            
    # If the username and password don't match, flash an error message and redirect back to the login page
    flash('Incorrect username or password.')
    return redirect(url_for('login_get'))

# Define the route for the logged-in page
@app.route('/loggedin')
@limiter.limit("5 per minute")
def loggedin():
    if 'username' in session:
        return render_template('loggedin.html', username=session['username'])
    else:
        return redirect(url_for('login_get'))

if __name__ == '__main__':
    # Obtain the certificate and private key from Let's Encrypt
    cert_path = 'cert.pem'
    key_path = 'key.pem'
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(cert_path, 'rb').read())
    key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open(key_path, 'rb').read())

    # Create an SSLContext object using the certificate and private key
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    app.run(host='0.0.0.0', port=8088, debug=True, ssl_context=ssl_context)
