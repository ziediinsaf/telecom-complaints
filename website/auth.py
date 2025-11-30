from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User , Note

from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from flask_login import login_user, login_required, current_user, logout_user
import time  


auth = Blueprint('auth', __name__)

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME_SECONDS = 60  

@auth.after_request
def add_csp_headers(response):
   
    csp_policy = {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
       
    }
   
   
    csp_header = "; ".join([f"{directive} {sources}" for directive, sources in csp_policy.items()])
   
    response.headers['Content-Security-Policy'] = csp_header
   
    return response



@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        login_type = request.form.get('login_type')

        user = User.query.filter_by(email=email).first()
        if user:
            if session.get('locked_out'):
                last_attempt_time = session.get('last_attempt_time', 0)
                elapsed_time = time.time() - last_attempt_time
                if elapsed_time < LOCKOUT_TIME_SECONDS:
                    remaining_time = LOCKOUT_TIME_SECONDS - elapsed_time
                    flash(f'Your account is locked. Please try again in {remaining_time:.0f} seconds.', category='error')
                    return redirect('/login')

                session.pop('locked_out')

            if check_password_hash(user.password, password) and (login_type == user.account_type):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                session["username"] = user.first_name
                session["account_type"] = user.account_type
                session.pop('login_attempts', None)

                if user.account_type == 'client':
                    return redirect(url_for('views.notes'))
                elif user.account_type == 'admin':
                    return redirect(url_for('views.all_notes'))
                elif user.account_type == 'technician':
                    return redirect(url_for('views.technician_notes'))
            else:

               
                flash('Incorrect password, try again.', category='error')
                session['login_attempts'] = session.get('login_attempts', 0) + 1
                if session.get('login_attempts', 0) >= MAX_LOGIN_ATTEMPTS:
                    flash('Too many login attempts. Your account is locked.', category='error')
                    session['locked_out'] = True
                    session['last_attempt_time'] = time.time()

        else:
            flash('Email does not exist.', category='error')

    else:
        if "username" in session:
            if session['account_type'] == 'client':
                return redirect(url_for('views.notes'))
            elif session['account_type'] == 'admin':
                return redirect(url_for('views.all_notes'))
            elif session['account_type'] == 'technician':
                return redirect(url_for('views.technician_notes'))  
        else:
            return render_template("login.html", user=current_user)

    return redirect('/login')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect("/login")



@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
       
        phone = request.form.get('phone')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
           
            new_user = User(account_type= "client", phone=phone,  email=email, first_name=first_name,
             password=generate_password_hash(
                password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            session["username"]=first_name
            session["account_type"]="client"
            flash('Account created!', category='success')
            # Redirection vers la page des notes après l'inscription
            return redirect(url_for('views.notes'))

    return render_template("sign_up.html", user=current_user)






   

@auth.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if "username" in session:
        if session["account_type"] == "admin":
            if request.method == 'POST':
                account_type = request.form.get('login_type')
                first_name = request.form.get('username')
                email = request.form.get('email')  
                password = request.form.get('password')
                phone = request.form.get('phone')
                city = request.form.get('city')
                region = request.form.get('region')
               
                user = User.query.filter_by(email=email).first()
               
                if user:
                    flash('Email already exists.', category='error')
                elif len(email) < 4:
                    flash('Email must be greater than 3 characters.', category='error')
                elif len(password) < 7:
                    flash('Password must be at least 7 characters.', category='error')
                else:
                    new_user = User(availability="Not available",
                                    account_type=account_type,
                                    phone=phone,
                                    city=city,
                                    region=region,
                                    email=email,
                                    first_name=first_name,
                                    password=generate_password_hash(password, method='pbkdf2:sha256'))
                   
                    db.session.add(new_user)
                    db.session.commit()
                   
                    login_user(new_user, remember=True)
                    flash('Account created!', category='success')
                   
                    if account_type == 'technician':
                        return redirect(url_for('views.all_accounts'))
                    elif account_type == 'admin':
                        return redirect(url_for('views.account_admin'))
                   
        else:
            return redirect("/")
    else:
        return redirect("/")
   
    return render_template("create_account.html", user=current_user)







            