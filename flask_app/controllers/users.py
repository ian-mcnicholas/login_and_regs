from typing import Collection
from flask_app import app
from flask import render_template,redirect,request,session,flash
from flask_bcrypt import Bcrypt
from flask_app.models.user import User

bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('/login.html')

@app.route('/success')
def success():
    if session['logged_in'] == True:
        return render_template('/index.html')
    return redirect('/')

# CREATE USER
@app.route('/users/create', methods=['POST'])
def register_user():
    if not User.validate_user(request.form):
        session['reg_submit'] = True
        session['login_submit'] = False
        return redirect('/')
    new_user = User.create_user(request.form)
    # STORE SESSION DATA
    session['user_id'] = new_user
    session['user_name'] = request.form['first_name']
    session['logged_in'] = True

    return redirect('/success')

# LOGIN 
@app.route('/login', methods=['POST'])
def login_user():
    data = { "email" : request.form["email"] }
    user_in_db = User.get_user(data)
    if not user_in_db:
        session['reg_submit'] = False
        session['login_submit'] = True
        flash("Email and/or password is incorrect")
        return redirect("/")
    if not bcrypt.check_password_hash(user_in_db[0]['password'], request.form['password']):
        flash("Email and/or password is incorrect")
        return redirect('/')
    # STORE SESSION 
    session['user_id'] = user_in_db[0]['id']
    session['user_name'] = user_in_db[0]['first_name']
    session['logged_in'] = True

    return redirect('/success')

# LOGOUT 
@app.route('/logout')
def logout():
    session.clear()
    session['logged_in'] = False

    return redirect('/')


