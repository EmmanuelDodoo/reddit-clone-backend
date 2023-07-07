from models import db, User, Token, Asset
from flask import Flask, request, redirect
import json
import re
from datetime import datetime
import os
import random
import base64

# ------------Config----------------------------------------
app = Flask(__name__)

main_db = "main.db"


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % main_db
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = False

db.init_app(app)

# ----------------------------------------------------

with app.app_context():
    # db.drop_all()
    db.create_all()


# -----------------------Helper Functions--------------------


def success_response(load, code=200, header=None):
    """
        Return a success response with given load `load` and 
        code, `code`. Code defaults to 200
    """
    if header:
        return json.dumps(load), code, header

    return json.dumps(load), code


def failure_response(msg, code=404):
    """
        Return a failure response with the given error message, `msg` and
        code, `code`. Code defaults to 404.

        Example: failure_response("test", 400) returns json.dumps({"error": "test"}), 400
    """
    return json.dumps({"error": msg}), code


def extract_token(request):
    """ Returns the token associated with `request`"""
    header = request.headers.get("Authorization")

    if not header:
        return False, failure_response("Missing Authorization", 400)

    token = header.replace("Bearer", "").strip()

    if not token:
        return False, failure_response("Missing session token", 400)

    return True, token


def verify_email(email: str):
    """ Returns true if `email` is a valid email."""

    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    re_match = re.search(pattern, email)

    return True if re_match else False


# -----------------------------------------------------------

@app.route("/api/")
def home():
    """The home end point of this api"""

    return "Home end point reached", 200


@app.route("/api/signup/", methods=["POST"])
def signup():
    """ Sign up a new user"""

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    # Verify the fields
    if not req_body.get("password") or not isinstance(req_body.get("password"), str):
        return failure_response("Bad request body", 400)

    if not req_body.get("username") or not isinstance(req_body.get("username"), str):
        return failure_response("Bad request body", 400)

    if req_body.get("imageURL") and not isinstance(req_body.get("imageURL"), str):
        return failure_response("Bad request body", 400)

    if not req_body.get("email") or not isinstance(req_body.get("email"), str):
        return failure_response("Bad request body", 400)
    if not verify_email(req_body.get("email", "")):
        return failure_response("Invalid email", 403)

    # Cross check for any similar user
    existing_user: User = User.query.filter_by(
        email=req_body.get("email")).first()
    if existing_user:
        return failure_response("User already exists", 400)

    # Create the new user and add to db
    new_user: User = User(req_body.get("username", ""), req_body.get(
        "email", ""), req_body.get("password", ""), req_body.get("imageURL", ""))
    db.session.add(new_user)
    db.session.commit()

    # Create a new session token
    token: Token = Token(new_user.id)
    db.session.add(token)
    db.session.commit()

    # Build response
    response = {
        "user_id": new_user.id,
        "username": new_user.username,
        "userImageURL": new_user.image_url,
        "karma": new_user.karma,
        "token_id": token.id,
        "token_value": token.value,
        "token_start": token.created_at,
        "token_expiration": token.expires_at
    }

    return success_response(response, 201)


@app.route("/api/login/", methods=["POST"])
def login():
    """ Login an existing user. Users can log in with either
        usernames or emails. Usernames take precedence over emails.
    """

    if not request.data:
        return failure_response("Missing request body", 400)

    req_body: dict = json.loads(request.data)

    # Get the user if there is a valid username
    if req_body.get("username") and isinstance(req_body.get("username"), str):
        user: User = User.query.filter_by(
            username=req_body.get("username")).first()
    # Get the user if there is a valid email
    elif req_body.get("email") and isinstance(req_body.get("email"), str) and verify_email(req_body.get("email", "")):
        user: User = User.query.filter_by(email=req_body.get("email")).first()

    else:
        return failure_response("Bad request body", 400)

    # Check the body password
    if not req_body.get("password") or not isinstance(req_body.get("password"), str):
        return failure_response("Bad request body", 400)

    if not user:
        return failure_response("Incorrect credentials", 401)

    if not user.verify(req_body.get("password", "")):
        return failure_response("Incorrect credentials", 401)

    # Create a new session token
    token: Token = Token(user.id)
    db.session.add(token)
    db.session.commit()

    # Build response
    response = {
        "user_id": user.id,
        "username": user.username,
        "userImageURL": user.image_url,
        "karma": user.karma,
        "token_id": token.id,
        "token_value": token.value,
        "token_start": token.created_at,
        "token_expiration": token.expires_at
    }

    return success_response(response)


@app.route("/api/upload/", methods=["POST"])
def upload_image():
    """Upload an image to the data base"""

    file = request.files.get("image")

    if not file or not file.content_type:
        return failure_response("Bad request", 400)

    temp = file.stream.read()
    enc = base64.b64encode(temp)
    img = Asset(enc.decode(), extension=file.content_type[6:])

    return success_response(img.serialize(), 201)


@app.route("/api/users/<int:id>/")
def get_user(id: int):
    """ Returns the user with the matching id.

    """

    user: User = User.query.filter_by(id=id).first()

    if not user:
        return failure_response("User not found")

    return success_response(user.full_serialize())


@app.route("/api/users/<int:id>/", methods=["PATCH"])
def update_user(id: int):
    """ Updates the fields of this user. 
        Only fields specified in the request body are updated.

        A valid token for the use ris required.
    """

    # User querying
    user: User = User.query.filter_by(id=id).first()
    if not user:
        return failure_response("User not found")

    if not request.data:
        return failure_response("Bad Request", 400)

    body: dict = json.loads(request.data)

    # Token verification
    sucess, message = extract_token(request)
    if not sucess:
        return message

    token: Token = Token.query.filter_by(value=message).first()
    if not token:
        return failure_response("Invalid session token", 401)

    if not token.verify(user.id):
        return failure_response("Invalid session token", 401)

    # Username
    if body.get("username"):
        if isinstance(body.get("username"), str):
            user.update_username(body.get("username", ""))
        else:
            return failure_response("Bad Request", 400)

    # Email
    if body.get("email"):
        if isinstance(body.get("email"), str):
            user.update_email(body.get("email", ""))
        else:
            return failure_response("Bad Request", 400)

    # Password
    # Expects raw password
    if body.get("password"):
        if isinstance(body.get("password"), str):
            user.update_password(body.get("password", ""))
        else:
            return failure_response("Bad Request", 400)

    # Image url
    if body.get("imageURL"):
        if isinstance(body.get("imageURL"), str):
            user.update_image_url(body.get("imageURL", ""))
        else:
            return failure_response("Bad Request", 400)

    # Karma
    if body.get("karma"):
        if isinstance(body.get("karma"), int):
            user.increase_karma(body.get("karma", 0))
        else:
            return failure_response("Bad request body", 400)

    return success_response(user.serialize(), 201)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
