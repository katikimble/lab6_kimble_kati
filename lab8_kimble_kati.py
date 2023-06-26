# Name: Kati Kimble
# Lab: 7
# Class: SDEV 300-7383
# Date: 12/05/2021

"""This program uses flask to generate a website using html,
css files, and a text file for password storage"""
import sys
from datetime import datetime
import secrets
from os import abort
import fileinput
import socket

from passlib.hash import sha256_crypt
from flask import Flask, request, render_template, redirect, url_for, flash, session

PASSWORD_FILE = "templates/registration_data.txt"
COMMON_PASSWORDS = "templates/CommonPassword.txt"
LOGGER_FILE = "templates/logger_file.txt"
POEMS_FILE = "templates/poems_file.txt"

app = Flask(__name__)

secret = secrets.token_urlsafe(32)
app.secret_key = secret


@app.route('/')
@app.route('/index')
def index():
    """This method renders the index page and date/time info"""
    now = datetime.now()  # current date and time
    date_time = now.strftime("%m/%d/%Y, %I:%M %p")  # format for date/time
    return render_template('index.html', date_time=date_time)


@app.route('/about')
def about():
    """This method renders the about page"""
    if not session.get('logged_in'):
        return render_template('index.html')
    return render_template('about.html')


def logger():
    """This method is used for logging failed login attempts"""
    try:
        now = datetime.now()  # current date and time
        date_time = now.strftime("%m/%d/%Y, %I:%M %p")  # format for date/time
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)  # IP address
        with open(LOGGER_FILE, "a", encoding="utf8") as file:
            file.write(f'{date_time}, {ip_address}\n')  # prints onto logger_file.txt
    except FileNotFoundError:
        print("This file was not found.")
        abort()


@app.route('/login', methods=['GET', 'POST'])
def login():
    """This method renders the login page"""
    failed_login_tracker = False
    if request.method == "POST":
        # gets the info from the form
        username = request.form["username"]
        password = request.form["password"]
        try:
            with open(PASSWORD_FILE, "r", encoding="utf8") as users:
                error = ""
                for record in users:
                    if len(record) == 0:
                        print('password file is empty')
                        return None
                    login_info = record.split(",")
                    # verify if the password and login info are together and correct
                    hash_pass = sha256_crypt.verify(password, login_info[1])
                    if username == login_info[0] and hash_pass:
                        name = login_info[2]
                        session['logged_in'] = True
                        # sets the username entered, to the session username
                        session['username'] = username
                        error = None
                    if not username:
                        error = "Username is required."
                    elif not password:
                        error = "Password is required."
                    # statement together for security purposes
                    elif username not in login_info or not hash_pass:
                        error = "Username is not registered or password is incorrect."
                        # used for logging failed attempts
                        failed_login_tracker = True
                    if error is None:
                        return redirect(url_for('home', name=name, error=error))

                if failed_login_tracker:
                    logger()

        except FileNotFoundError:
            print("This file was not found.")
            abort()

        flash(error)

    return render_template('login.html')


def checknotreg(username_input):
    """ Check if the given username does not
    already exist in our password file"""
    try:
        with open(PASSWORD_FILE, "r", encoding="utf8") as users:
            for record in users:
                u_name, _, _, _, _, _ = record.split(",")
                if u_name == username_input:
                    return True
            return False

    except FileNotFoundError:
        print("This file was not found.")
        abort()
        return False


def replace(file, search_exp, replace_exp):
    """This method is used for replacing the line in file with new hash secret"""
    for line in fileinput.input(file, inplace=1):
        line = line.replace(search_exp, replace_exp)
        sys.stdout.write(line)


@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    """This method renders update password page and allows user to update password"""
    if not session.get('logged_in'):
        return render_template('index.html')
    if request.method == "POST":
        # gets the info from the form
        username = request.form["username"]
        with open(COMMON_PASSWORDS, "r", encoding="utf8") as common_passwords:
            common = common_passwords.read()
        password = request.form["password"]
        error = None
        if not username:
            error = "Username is required."
        elif not password:
            error = "New password is required."
        elif password in common:
            # will seach in CommonPassword.txt and display
            # error/prevent reset if common secret is chosen
            error = "This password is too common and should not be used.  " \
                    "Please enter a different password."
        elif username != session.get('username'):
            # making sure only the password for the username in session can be changed
            error = "Please enter your correct username to change your password."

        if error is None:
            try:
                with open(PASSWORD_FILE, "r", encoding="utf8") as users:
                    passwords = users.readlines()
                for line in passwords:
                    login_info = line.split(",")
                    # finds the username and matches it to the index in the file
                    if username == login_info[0]:
                        current_password = login_info[1]
                        new_hash_pass = sha256_crypt.hash(password)
                        # uses this method to replace that password with the new hash pass
                        replace(PASSWORD_FILE, current_password, new_hash_pass)
                        return redirect(url_for('home'))
            except FileNotFoundError:
                print("This file was not found.")
                abort()

        flash(error)

    return render_template('update_password.html')


@app.route('/poems')
def poems():
    """This method renders the poems page"""
    if not session.get('logged_in'):
        return render_template('index.html')
    return render_template('poems.html')


@app.route('/poems', methods=['POST'])
def my_form_post():
    text = request.form['text']
    with open(POEMS_FILE, "a", encoding="utf8") as file:
        file.writelines(f'{text}\n')
    return render_template('home.html')

@app.route("/logout")
def logout():
    """This method logs the user out and returns to index page"""
    session['logged_in'] = False
    return index()


@app.route('/register', methods=['GET', 'POST'])
def register():
    """This method renders the events page"""
    if request.method == "POST":
        # gets the information from the form
        first_name = request.form.get('first name')
        last_name = request.form.get('last name')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('address')
        error = None
        if not username:
            error = 'Please enter your Username.'
        elif not password:
            error = 'Please enter your Password.'
        elif not first_name:
            error = 'Please enter your first name.'
        elif not last_name:
            error = 'Please enter your last name.'
        elif not email:
            error = 'Please enter your email address.'
        elif checknotreg(username):
            error = 'This username already exists. Please select another username.'
        if error is None:
            # convert password to encrypted version for storage
            hash_pass = sha256_crypt.hash(password)
            user = f'{username},{hash_pass},{first_name},{last_name},{email},\n'
            try:
                with open(PASSWORD_FILE, "a", encoding="utf8") as file:
                    # writing to the text file
                    file.writelines(user)
                return redirect(url_for('login'))
            except FileNotFoundError:
                print("This file was not found.")
                abort()
        # flashes errors
        flash(error)
    return render_template('register.html')


@app.route('/home', methods=['GET', 'POST'])
def home():
    """Creates home path.  Returns to index page if not logged in."""
    if not session.get('logged_in'):
        return render_template('index.html')
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True)
