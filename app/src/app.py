from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path
# import socket

# Use bcrypt for password handling
import bcrypt

# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_address = ('localhost', 5001)
# server_socket.bind(server_address)  

PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = ":"

app = Flask(__name__)
# The secret key here is required to maintain sessions in flask
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

# Initialize Database file if not exists.
if not os.path.exists(PASSWORDFILE):
    open(PASSWORDFILE, 'w').close()


# @app.route('/')
# def home():

#     # TODO: Check if user is logged in
#     # if user is logged in
#     #    return render_template('loggedin.html')

#     return render_template('home.html')


@app.route('/')
def home():

    # Display the username of a logged in user

    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return render_template('home.html')



# Display register form
@app.route('/register', methods=['GET'])
def register_get():


    return render_template('register.html')


##



# Handle registration data
@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']

    # Validate the username and password
    if not username or not password:
        flash('Please enter a username and password.')
        return redirect(url_for('register_get'))

    # Hash the password with bcrypt before storing it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store the username and hashed password in the password file
    with open(PASSWORDFILE, 'a') as f:
        f.write(f'{username}{PASSWORDFILEDELIMITER}{hashed_password.decode("utf-8")}\n')

    flash('Registration successful! Please log in.')
    return redirect(url_for('login_get'))


# Display login form
@app.route('/login', methods=['GET'])
def login_get():


    return render_template('login.html')


# Handle login credentials
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']

    # Validate the username and password against the stored passwords
    with open(PASSWORDFILE, 'r') as f:
        for line in f:
            stored_username, stored_password = line.strip().split(PASSWORDFILEDELIMITER)
            if username == stored_username and bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                session['username'] = username
                return redirect(url_for('loggedin'))

    flash('Incorrect username or password.')
    return redirect(url_for('login_get'))

# checks if the user is logged in by checking if the 'username' key is present in the session dictionary.
@app.route('/loggedin')
def loggedin():
    if 'username' in session:
        return render_template('loggedin.html', username=session['username'])
    else:
        return redirect(url_for('login_get'))


if __name__ == '__main__':

    # TODO: Add TSL
    app.run(host='10.0.0.8', port=8000, debug=True, ssl_context=('cert.pem', 'key.pem'))


