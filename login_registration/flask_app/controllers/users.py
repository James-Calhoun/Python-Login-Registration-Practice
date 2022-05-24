from xml.dom import UserDataHandler
from flask import render_template, session, flash, request, redirect
from flask_app import app
from flask_app.models.user import User



from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)


@app.route('/')
def log_and_reg():
    return render_template('log_and_reg.html')


@app.route('/users/login', methods=['POST'])
def login():
    if not User.validate_login(request.form):
        return redirect('/')

    user_data = {
        'email': request.form['email']
    }
    user = User.get_user_by_email(user_data)
    
    if user:
        if not bcrypt.check_password_hash(user.password, request.form['password']):
            flash('Email/Password combination is incorrect')
            return redirect('/')
        
        # if password has matches stored hash in database
        session['user_id'] = user.id
        flash('Login was successful!', 'info')
        return redirect('/dashboard')
    # user was not found
    flash('Email is not tied to account')
    return redirect('/')

@app.route('/users/register', methods=['POST'])
def register():
    # if form data is invalid (False), redirect to home page
    if not User.validate_register(request.form):
        return redirect('/')

    # if form data is valid (True), hash password, create user data, and put it in session to determine at any point if a user is logged in or not
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print(pw_hash)

    register_data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': pw_hash
    }

    # This works because INSERT statements (queries) with mysqlconnection.py will return the auto-incremented id
    user_id = User.register_user(register_data)
    session['user_id'] = user_id
    flash('Registration was successful!', 'info')
    return redirect('/dashboard')


@app.route('/dashboard')
def dashboard():
    # Get user from the session we created during registration
    user_data = {
        'id': session['user_id']
    }
    user = User.get_user_by_id(user_data)
    return render_template('dashboard.html', user = user)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')