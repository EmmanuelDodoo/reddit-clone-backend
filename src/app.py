from models import db, User, Token, Asset, Post
from flask import Flask, request, redirect, Request
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


def extract_token(request: Request):
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


def verify_token(userid: int, request: Request):
    """ Checks the existence of token in `request` and
        verifies token for `userid`.

        Returns a 2 tuple of form:
            tuple[0]: boolean - whether the token verification was successful
            tuple[1]: the message associated with the verification.  
    """
    success, message = extract_token(request)
    if not success:
        return success, message

    token: Token = Token.query.filter_by(value=message).first()
    if not token or not token.verify(userid):
        return False, failure_response("Invalid session token", 401)

    return True, success_response(token.serialize())

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
    # by email
    existing_user: User = User.query.filter_by(
        email=req_body.get("email")).first()
    if existing_user:
        return failure_response("User already exists", 400)
    # by username
    existing_user: User = User.query.filter_by(
        username=req_body.get("usename")).first()
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


@app.route("/api/users/<int:uid>/posts/")
def get_user_posts(uid: int):
    """Returns all the posts of uid"""

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    return success_response(user.get_all_posts())


@app.route("/api/users/<int:uid>/posts/<int:pid>/upvote/", methods=["PATCH"])
def upvote_post(uid: int, pid: int):
    """ 
        Upvote a post. User karma is increased by 2
        No change is made if the user has already upvoted this post.

        Requires Authentication

    """
    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not Found", 404)

    post: Post = Post.query.filter_by(id=pid).first()
    if not post:
        return failure_response("Post not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    # Check if post is already upvoted
    if not pid in user.get_upvoted_posts():
        user.add_post_upvote(pid)
        user.increase_karma(2)
        post.upvote()

    return success_response(post.serialize(), 201)


@app.route("/api/users/<int:uid>/posts/<int:pid>/upvote/reset/", methods=["PATCH"])
def reset_upvote(uid: int, pid: int):
    """ Resets a user's upvote on a post. 
        No change is made if the post was not previously upvoted on.

        Requires Authentication
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    post: Post = Post.query.filter_by(id=pid).first()
    if not post:
        return failure_response("Post not found")

    success, message = verify_token(uid, request)

    if not success:
        return message

    if pid in user.get_upvoted_posts():
        user.remove_post_upvote(pid)
        post.downvote()

    return success_response(post.serialize(), 201)


@app.route("/api/users/<int:uid>/posts/<int:pid>/downvote/", methods=["PATCH"])
def downvote_post(uid: int, pid: int):
    """ 
        Downvote a post.
        No change is made if the user has already upvoted this post.

        Requires Authentication

    """
    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not Found", 404)

    post: Post = Post.query.filter_by(id=pid).first()
    if not post:
        return failure_response("Post not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    # Check if post is already downvoted
    if not post.id in user.get_downvoted_posts():
        user.add_post_downvote(post.id)
        post.downvote()

    return success_response(post.serialize(), 201)


@app.route("/api/users/<int:uid>/posts/<int:pid>/downvote/reset/", methods=["PATCH"])
def reset_downvote(uid: int, pid: int):
    """ Reset's a user's downvote on a post. 
        No change is made if the post was not previously downvoted on.

        Requires Authentication
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    post: Post = Post.query.filter_by(id=pid).first()
    if not post:
        return failure_response("Post not found")

    success, message = verify_token(uid, request)

    if not success:
        return message

    if pid in user.get_downvoted_posts():
        user.remove_post_downvote(pid)
        post.upvote()

    return success_response(post.serialize(), 201)


@app.route("/api/posts/", methods=["POST"])
def create_post():
    """ Create a post.
        User karma is increased by 47 if successful

        Requires an Authorization token
    """

    if not request.data:
        return failure_response("Bad Request", 400)

    body: dict = json.loads(request.data)

    # Validate the request body
    if not body.get("userid") or not isinstance(body.get("userid"), int):
        return failure_response("Bad Request", 400)

    if not body.get("title") or not isinstance(body.get("title"), str):
        return failure_response("Bad Request", 400)

    if body.get("imagePresent") == None or not isinstance(body.get("imagePresent"), bool):
        return failure_response("Bad Request", 400)

    if body.get("contents") and not isinstance(body.get("contents"), str):
        return failure_response("Bad Request", 400)

    if body.get("imagePresent"):
        if not body.get("imageURL") or not isinstance(body.get("imageURL"), str):
            return failure_response("Bad Request", 400)

    # Validate user existence
    user: User = User.query.filter_by(id=body.get("userid")).first()

    if not user:
        return failure_response("User not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    post: Post = Post(
        userid=body.get("userid", 0),
        title=body.get("title", ""),
        contents=body.get("contents", ""),
        image_present=body.get("imagePresent", ""),
        image_url=body.get("imageURL", "")
    )

    # Add and commit changes
    db.session.add(post)
    db.session.commit()

    # upvote the post. Post doesn't have an id until it's added to the database
    user.add_post_upvote(post.id)
    user.increase_karma(47)

    return success_response(post.serialize(), 201)


@app.route("/api/posts/<int:pid>/")
def get_post(pid: int):
    """ Return the post with matching id"""

    post: Post = Post.query.filter_by(id=pid).first()

    if not post:
        return failure_response("Post not found")

    return success_response(post.serialize())


@app.route("/api/testing/")
def testing():
    """Testing stuff"""

    user: User = User.query.filter_by(id=1).first()

    user.remove_post_upvote(2)

    return success_response(user.full_serialize())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
