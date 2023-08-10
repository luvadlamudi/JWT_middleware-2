from flask import Flask, request, jsonify, make_response, session, redirect, url_for, render_template
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# Set the secret key for the Flask session
app.secret_key = 'sJe_eW5z5IGS8YJ1YW4'

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return redirect("/login")

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'Message': 'Invalid token'}), 403
        return func(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    if not session.get('logged_in'):
        return redirect('/login')
    else:
        return 'logged in currently'

@app.route('/public')
def public():
    return 'For Public'

@app.route('/auth')
def auth():
    if not session.get('logged_in'):
        return redirect('/login')
    else:
        return 'JWT is verified. Welcome to your dashboard!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] and request.form['password'] == 'a':
            session['logged_in'] = True

            token = jwt.encode({
                'user': request.form['username'],
                'exp': datetime.utcnow() + timedelta(minutes=1)
            },
                app.config['SECRET_KEY'])
            return jsonify({'token': token})
        else:
            return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})
    else:
        # Render the login form for GET requests
        return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session['logged_in'] = False
    
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == "__main__":
    app.run(debug=True)
