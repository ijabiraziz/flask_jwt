from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    create_refresh_token,
    get_jwt_identity,
)
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "mysecretsuperkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
jwt = JWTManager(app)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return self.username


@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully!"})


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    user = User.query.filter_by(username=username).first()
    if not user or user.password != password:
        return jsonify({"message": "Invalid credentials!"}), 401

    # Set token expiration to 1 hour
    expires = timedelta(hours=1)
    access_token = create_access_token(identity=user.id, expires_delta=expires)
    # generate refresh token
    refresh_token = create_refresh_token(identity=user.id)
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


@app.route("/success", methods=["GET"])
@jwt_required()
def protected():
    return jsonify({"Message": "Successfully installed Flask-JWT!"})


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": access_token})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
