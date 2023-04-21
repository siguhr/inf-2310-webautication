from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path
import ssl
import bcrypt
import OpenSSL

app = Flask(__name__)
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = ":"

if not os.path.exists(PASSWORDFILE):
    open(PASSWORDFILE, 'w').close()

@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return render_template('home.html')

@app.route('/register', methods=['GET'])
def register_get():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    if not username or not password:
        flash('Please enter a username and password.')
        return redirect(url_for('register_get'))
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open(PASSWORDFILE, 'a') as f:
        f.write(f'{username}{PASSWORDFILEDELIMITER}{hashed_password.decode("utf-8")}\n')
    flash('Registration successful! Please log in.')
    return redirect(url_for('login_get'))

@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    with open(PASSWORDFILE, 'r') as f:
        for line in f:
            stored_username, stored_password = line.strip().split(PASSWORDFILEDELIMITER)
            if username == stored_username and bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                session['username'] = username
                return redirect(url_for('loggedin'))
    flash('Incorrect username or password.')
    return redirect(url_for('login_get'))

@app.route('/loggedin')
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
