from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request,session
from werkzeug.security import check_password_hash, generate_password_hash
from jinja2 import Environment, PackageLoader, select_autoescape
from tempfile import mkdtemp
from flask_session import Session, sessions


app = Flask(__name__)


app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True




db = SQL("sqlite:///Database.db")


@app.route("/")
def index():
    return render_template("signUp.html")

@app.route("/signUp.html")
def signUpTemplate():
    return render_template("signUp.html")


@app.route("/index.html")
def home() :
    return render_template("index.html")

@app.route("/sign up", methods=["GET", "POST"])
def signUp():
    if request.method == "POST":
        name = request.form.get("fullName")
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        gender = request.form.get("gender")
        username_confirmtion = db.execute("SELECT * FROM Users WHERE user_username = ?", username)
        email_confirmation  =  db.execute("SELECT * FROM Users WHERE user_email = ?", email) 
        
        if len(username_confirmtion) != 0:
            return render_template("signUp.html", error = "هذا المستخدم موجود بالفعل")
        elif len(email_confirmation) != 0:
            return render_template("signUp.html", error = "هذا البريد موجود بالفعل")

        else:
            hash = generate_password_hash(
                password, method="pbkdf2:sha256", salt_length=8
            )

            db.execute("INSERT INTO Users(user_fullname, user_username, hash, user_email, user_gender) VALUES (?, ?, ?, ?, ?)", name, username, hash, email, gender)

            return redirect("/login.html")
    else:
        render_template("signUp.html")



@app.route("/login.html")
def loginTemplate():
    return render_template("login.html")



@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()


    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email.find(".com") != "-1":
            user_login = db.execute("SELECT * FROM Users WHERE user_username = ?", email)
            if len(user_login) != 1 or not check_password_hash(user_login[0]["hash"], password):
                return render_template("login.html", error = "خطا فى اسم المستخدم او كلمه المرور")

            session["user_id"] = user_login[0]["user_id"]
            return redirect("/index.html")

        else:
            user_login = db.execute("SELECT * FROM Users WHERE user_email = ?", email)
            if len(user_login) != 1 or not check_password_hash(user_login[0]["hash"], password):
                    return render_template("login.html", error = "خطا فى اسم المستخدم او كلمه المرور")

            session["user_id"] = user_login[0]["user_id"]
            return redirect("/index.html")

    else:
        return render_template("login.html")
    

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/signUp.html")