from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path
import bcrypt
import ssl
from OpenSSL import SSL, crypto

# Set up the password file path and delimiter
PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = ":"

# Create a Flask app instance
app = Flask(__name__)

# Set a secret key to enable sessions
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

# Check if the password file exists, and create it if it doesn't
if not os.path.exists(PASSWORDFILE):
    open(PASSWORDFILE, 'w').close()

# Create an SSL context and load the certificate and private key
context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_privatekey_file('privkey.pem')
context.use_certificate_file('fullchain.pem')

# Define the home route for the app
@app.route('/')
def home():
    # If the user is logged in, render the home page with their username
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    # If the user is not logged in, render the home page without a username
    else:
        return render_template('home.html')

# Define the register route for the app
@app.route('/register', methods=['GET'])
def register_get():
    # Render the registration form
    return render_template('register.html')

# Define the registration post route for the app
@app.route('/register', methods=['POST'])
def register_post():
    # Get the username and password from the registration form
    username = request.form['username']
    password = request.form['password']

    # If either the username or password fields are empty, redirect to the registration form with an error message
    if not username or not password:
        flash('Please enter a username and password.')
        return redirect(url_for('register_get'))

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Write the username and hashed password to the password file
    with open(PASSWORDFILE, 'a') as f:
        f.write(f'{username}{PASSWORDFILEDELIMITER}{hashed_password.decode("utf-8")}\n')

    # Redirect to the login form with a success message
    flash('Registration successful! Please log in.')
    return redirect(url_for('login_get'))

# Define the login route for the app
@app.route('/login', methods=['GET'])
def login_get():
    # Render the login form
    return render_template('login.html')

# Define the login post route for the app
@app.route('/login', methods=['POST'])
def login_post():
    # Get the username and password from the login form
    username = request.form['username']
    password = request.form['password']

    # Check each line of the password file for a matching username and password
    with open(PASSWORDFILE, 'r') as f:
        for line in f:
            stored_username, stored_password = line.strip().split(PASSWORDFILEDELIMITER)
            # If the username and password match, log the user in and redirect to the logged in page
            if username == stored_username and bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                session['username'] = username
                return redirect(url_for('loggedin'))

    # If no matching username and password is found, redirect to the login form with an error message
    flash('Incorrect username or password.')
    return redirect(url_for('login_get'))

# Defines the route for '/loggedin'
@app.route('/loggedin') 
def loggedin():
    # Check if the user is logged in by checking if their username is in the session
    if 'username' in session: 
        # If the user is logged in, render the 'loggedin.html' template with their username as a parameter
        return render_template('loggedin.html', username=session['username']) 
    else:
        # If the user is not logged in, redirect them to the login page using the 'login_get' function defined earlier```
        return redirect(url_for('login_get')) 


if __name__ == '__main__':
    app.run(ssl_context=context)
