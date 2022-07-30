from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import bcrypt


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///users.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# create users model 
class User(db.Model): 
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column('username', db.String)
    email = db.Column('email', db.String)
    salt = db.Column('salt', db.String)
    hash_pw = db.Column('hash_pw', db.String)

    



@app.route('/register', methods=['POST'])
def register(): 
    if request.method == 'POST':
        
        username = request.json['username']
        email = request.json['email']
        db_email = User.query.filter_by(email=email).first()
        if db_email != None: 
            return 'This user is already registered'
        else: 
            salt = bcrypt.gensalt()
            bytes_pw = request.json['password'].encode('utf-8')
            hash_pw = bcrypt.hashpw(bytes_pw, salt) 
            user = User(username=username, email=email, salt=salt, hash_pw=hash_pw)

            db.session.add(user)
            db.session.commit()
            return 'You submitted a user'
    return 'Sorry, there was an error - unable to add user.'

@app.route('/login', methods=['POST'])        
def login(): 
    if request.method == 'POST':
        # username = request.args.get('username')
        email = request.json['email']
        db_email = User.query.filter_by(email=email).first()
        if db_email != None: 
            # retrieve stored salt from db
            salt = User.query.filter_by(email=email).first().salt
            bytes_pw = request.json['password'].encode('utf-8')
            hash_pw = bcrypt.hashpw(bytes_pw, salt) 
            # retrieve password from the db that matches the email submitted in the request 
            db_pw = User.query.filter_by(email=email).first().hash_pw
            # check if hash of that passowrd matches hash of password submitted
            # if yes, login 
            if hash_pw == db_pw: 
                return 'You are logged in.'
            # if no, return error 
            else: 
                return 'Password and email combination do not match.'
        else: 
            return 'This user is not registered. Please register.'
            
    return 'Sorry, there was an error - unable to login.'


if __name__ == '__main__': 
    app.run(debug=True)