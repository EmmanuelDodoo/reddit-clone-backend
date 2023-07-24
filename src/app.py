from models import db, User, Token, Asset, Post, Comment, Subreddit
from flask import Flask, request, Request
import json
import re
from sqlalchemy import func, desc
import base64
from waitress import serve

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


@app.route("/")
def greeting():
    return "Home of the reddit clone api"


@app.route("/api/home/")
@app.route("/api/")
def home():
    """Fetches a posts in a random order"""

    output = [p.serialize() for p in Post.query.order_by(func.random()).all()]

    return success_response({"home": output})


@app.route("/api/popular/")
def popular():
    """ Fetches post according to their popularity"""

    output = [p.serialize() for p in Post.query.order_by(desc("votes")).all()]

    return success_response({"popular": output})


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
        "userId": new_user.id,
        "username": new_user.username,
        "userImageURL": new_user.image_url,
        "karma": new_user.karma,
        "joined": new_user.joined,
        "tokenId": token.id,
        "tokenValue": token.value,
        "tokenStart": token.created_at,
        "tokenExpiration": token.expires_at
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
        "userId": user.id,
        "username": user.username,
        "userImageURL": user.image_url,
        "karma": user.karma,
        "joined": user.joined,
        "tokenId": token.id,
        "tokenValue": token.value,
        "tokenStart": token.created_at,
        "tokenExpiration": token.expires_at
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

    return success_response(user.serialize())


@app.route("/api/users/<int:id>/", methods=["PATCH"])
def update_user(id: int):
    """ Updates the fields of this user. 
        Only fields specified in the request body are updated.

        Requires Authentication 
    """

    # User querying
    user: User = User.query.filter_by(id=id).first()
    if not user:
        return failure_response("User not found")

    if not request.data:
        return failure_response("Bad Request", 400)

    body: dict = json.loads(request.data)

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

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

    db.session.commit()
    return success_response(user.serialize(), 201)


@app.route("/api/users/<int:uid>/posts/")
def get_user_posts(uid: int):
    """Returns all the posts of uid"""

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    return success_response({"posts": user.get_all_posts()})


@app.route("/api/users/<int:uid>/posts/upvoted/")
def get_user_upvoted_posts(uid: int):
    """ Returns all posts upvoted by a user. 

    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    # Token verification
    # success, message = verify_token(user.id, request)
    # if not success:
    #     return message

    return success_response({"upvotedPosts": user.get_upvoted_posts()})


@app.route("/api/users/<int:uid>/posts/downvoted/")
def get_user_downvoted_posts(uid: int):
    """ Returns all posts downvoted by a user. 

    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    # Token verification
    # success, message = verify_token(user.id, request)
    # if not success:
    #     return message

    return success_response({"downvotedPosts": user.get_downvoted_posts()})


@app.route("/api/users/<int:uid>/comments/")
def get_user_comments(uid: int):
    """ Returns all user comments"""

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    return success_response({"comments": user.get_all_comments()})


@app.route("/api/users/<int:uid>/comments/upvoted/")
def get_user_upvoted_comments(uid: int):
    """ Returns all comments upvoted by a user
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    # Token verification
    # success, message = verify_token(user.id, request)
    # if not success:
    #     return message

    return success_response({"upvotedComments": user.get_upvoted_comments()})


@app.route("/api/users/<int:uid>/comments/downvoted/")
def get_user_downvoted_comments(uid: int):
    """ Returns all comments downvoted by a user
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    # Token verification
    # success, message = verify_token(user.id, request)
    # if not success:
    #     return message

    return success_response({"downvotedComments": user.get_downvoted_comments()})


@app.route("/api/users/<int:uid>/subreddits/")
def get_user_subreddits(uid: int):
    """ Fetches all subreddits the `uid` has subscribed to
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    return success_response({"subreddits": user.get_subscriptions()})


# Posts
@app.route("/api/users/<int:uid>/posts/<int:pid>/upvote/", methods=["POST"])
def upvote_post(uid: int, pid: int):
    """ 
        Upvote a post. User karma is increased by 2
        No change is made if the user has already upvoted this post.

        `uid` should match the user currently doing the upvote

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
    if not post in user.get_upvoted_posts():
        user.upvote_post(post)
        user.increase_karma(2)

    db.session.commit()

    return success_response(post.serialize(), 201)


@app.route("/api/users/<int:uid>/posts/<int:pid>/downvote/", methods=["POST"])
def downvote_post(uid: int, pid: int):
    """ 
        Downvote a post.
        No change is made if the user has already upvoted this post.

        `uid` should match the user  currently doing the downvote

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
    if not post in user.get_downvoted_posts():
        user.downvote_post(post)

    db.session.commit()
    return success_response(post.serialize(), 201)


@app.route("/api/users/<int:uid>/posts/<int:pid>/votes/reset/", methods=["POST"])
def reset_post_vote(uid: int, pid: int):
    """ Reset's a user's vote on a post. No change is made if
        the post was not previously voted on

        `uid` should match the user  currently doing the reset

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

    user.reset_post_vote(post)
    db.session.commit()

    return success_response(post.serialize(), 201)


@app.route("/api/posts/", methods=["POST"])
def create_post():
    """ Create a post.
        User karma is increased by 47 if successful.
        Users automatically upvote their own post when created.

        Current implementation assumes subreddit id is always present

        Requires an Authorization token
    """

    if not request.data:
        return failure_response("Missing request body", 400)

    body: dict = json.loads(request.data)

    # Validate the request body
    if not body.get("userId") or not isinstance(body.get("userId"), int):
        return failure_response("Bad Request", 400)

    if not body.get("title") or not isinstance(body.get("title"), str):
        return failure_response("Bad Request", 400)

    if body.get("imagePresent") == None or not isinstance(body.get("imagePresent"), bool):
        return failure_response("Bad Request", 400)

    if body.get("contents") and not isinstance(body.get("contents"), str):
        return failure_response("Bad Request", 400)

    if not body.get("subredditId") or not isinstance(body.get("subredditId"), int):
        return failure_response("Bad request", 400)

    if body.get("imagePresent"):
        if not body.get("imageURL") or not isinstance(body.get("imageURL"), str):
            return failure_response("Bad Request", 400)

    # Validate user existence
    user: User = User.query.filter_by(id=body.get("userId")).first()

    if not user:
        return failure_response("User not found")

    # Validate subreddit
    subreddit: Subreddit = Subreddit.query.filter_by(
        id=body.get("subredditId", 0)).first()
    if not subreddit:
        return failure_response("Subreddit not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    post: Post = Post(
        user_id=body.get("userId", 0),
        title=body.get("title", ""),
        subreddit_id=body.get("subredditId"),
        contents=body.get("contents", ""),
        image_present=body.get("imagePresent", ""),
        image_url=body.get("imageURL", "")
    )

    db.session.add(post)

    user.upvote_post(post)
    user.increase_karma(47)

    db.session.commit()

    return success_response(post.serialize(), 201)


@app.route("/api/posts/<int:pid>/")
def get_specific_post(pid: int):
    """ Return the post with matching id"""

    post: Post = Post.query.filter_by(id=pid).first()

    if not post:
        return failure_response("Post not found")

    return success_response(post.serialize())


# Comments
@app.route("/api/posts/<int:pid>/comments/")
def get_post_comments(pid: int):
    """ Fetch all comments under a post"""

    # Post verification
    post: Post = Post.query.filter_by(id=pid).first()
    if not post:
        return failure_response("Post not found")

    return success_response({"comments": post.get_all_comments()})


@app.route("/api/posts/<int:pid>/comments/<int:cid>/")
def get_specific_comment(pid: int, cid: int):
    """ Fetch a specific comment"""

    post: Post = Post.query.filter_by(id=pid).first()
    if not post:
        return failure_response("Post not found")

    comment: Comment = Comment.query.filter_by(id=cid).first()
    if not comment:
        return failure_response("Comment not found")

    return success_response(comment.serialize())


@app.route("/api/posts/<int:pid>/comment/", methods=["POST"])
def create_comment(pid: int):
    """ Create a comment under a post.
        User's karma is increased by 5 when successful
        Users automatically upvote their own post when created.

        Authentication required.    
    """

    # Validate post
    post: Post = Post.query.filter_by(id=pid).first()

    if not post:
        return failure_response("Post not Found")

    # validate request body
    if not request.data:
        return failure_response("Bad Request", 400)

    body: dict = json.loads(request.data)

    if not body.get("userId") or not isinstance(body.get("userId"), int):
        return failure_response("Bad Request", 400)

    if not body.get("contents") or not isinstance(body.get("contents"), str):
        return failure_response("Bad Request", 400)

    if not body.get("ancestorId") or not isinstance(body.get("ancestorId"), int):
        return failure_response("Bad Request", 400)

    # Validate user
    user: User = User.query.filter_by(id=body.get("userId", 0)).first()

    if not user:
        return failure_response("User not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    # Check if ancestor id is valid
    # ancestor id is either a valid comment id or -1
    if body.get("ancestorId", 0) > 0:
        ancestor_comment = Comment.query.filter_by(
            id=body.get("ancestorId", 0)).first()
        if not ancestor_comment:
            return failure_response("Ancestor Comment not found")

        else:
            new_comment = Comment(user_id=body.get("userId", 0), post_id=pid, ancestor_id=body.get(
                "ancestorId", 0), contents=body.get("contents", ""))
    else:
        new_comment = Comment(body.get("userId", 0), pid,
                              None, body.get("contents", ""))

    db.session.add(new_comment)

    #
    user.increase_karma(5)
    user.upvote_comment(new_comment)

    db.session.commit()

    return success_response(new_comment.serialize(), 201)


@app.route("/api/users/<int:uid>/comments/<int:cid>/upvote/", methods=["POST"])
def upvote_comment(uid: int, cid: int):
    """ 
        Upvote a comment. User karma is increased by 1
        No change is made if the user has already upvoted this comment.

        `uid` should match the user  currently doing the upvote

        Requires Authentication

    """
    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not Found", 404)

    comment: Comment = Comment.query.filter_by(id=cid).first()
    if not comment:
        return failure_response("Comment not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    # user method handles duplicate upvotes and comment vote count
    user.upvote_comment(comment)
    user.increase_karma(1)

    db.session.commit()

    return success_response(comment.serialize(), 201)


@app.route("/api/users/<int:uid>/comments/<int:cid>/downvote/", methods=["POST"])
def downvote_comment(uid: int, cid: int):
    """ 
        Downvote a comment.
        No change is made if the user has already downvoted this comment.

        `uid` should match the user  currently doing the downvote

        Requires Authentication

    """
    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not Found", 404)

    comment: Comment = Comment.query.filter_by(id=cid).first()
    if not comment:
        return failure_response("Comment not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    # user method handles duplicate upvotes and comment vote count
    user.downvote_comment(comment)

    db.session.commit()

    return success_response(comment.serialize(), 201)


@app.route("/api/users/<int:uid>/comments/<int:cid>/votes/reset/", methods=["POST"])
def reset_comment_vote(uid: int, cid: int):
    """ Reset's a user's vote on a comment. No change is made if
        the comment was not previously voted on.

        `uid` should match the user  currently doing the reset

        Requires Authentication
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not Found", 404)

    comment: Comment = Comment.query.filter_by(id=cid).first()
    if not comment:
        return failure_response("Comment not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    user.reset_comment_vote(comment)
    db.session.commit()

    return success_response(comment.serialize(), 201)


# Subreddits
@app.route("/api/subreddit/", methods=["POST"])
def create_subreddit():
    """ Creates a new subreddit. The creating user is automatically
        subscribed to the new subreddit.

        Requires authentication
    """

    if not request.data:
        return failure_response("Missing request body", 400)

    body: dict = json.loads(request.data)

    if not body.get("name") or not isinstance(body.get("name"), str):
        return failure_response("Bad Request", 400)

    if not body.get("imageURL") or not isinstance(body.get("imageURL"), str):
        return failure_response("Bad Request", 400)

    if not body.get("thumbnailURL") or not isinstance(body.get("thumbnailURL"), str):
        return failure_response("Bad Request", 400)

    if not body.get("about") or not isinstance(body.get("about"), str):
        return failure_response("Bad Request", 400)

    if body.get("rules") == None or not isinstance(body.get("rules"), list) \
            or not all(isinstance(rule, str) for rule in body.get("rules", [])):
        return failure_response("Bad Request", 400)

    if not body.get("userId") or not isinstance(body.get("userId"), int):
        return failure_response("Bad Request", 400)

    # User verification
    user: User = User.query.filter_by(id=body.get("userId")).first()
    if not user:
        return failure_response("User not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    subreddit = Subreddit(
        name=body.get("name", ""),
        image_url=body.get("imageURL", ""),
        thumbnail_url=body.get("thumbnailURL", ""),
        about=body.get("about", ""),
        rules=body.get("rules", [])
    )

    db.session.add(subreddit)
    user.subscribe(subreddit)
    db.session.commit()

    return success_response(subreddit.serialize(), 201)


@app.route("/api/subreddit/<int:sid>/")
def get_specific_subreddit(sid: int):
    """ Fetch a specific subreddit"""

    subreddit: Subreddit = Subreddit.query.filter_by(id=sid).first()
    if not subreddit:
        return failure_response("Subreddit not found")

    return success_response(subreddit.serialize(), 200)


@app.route("/api/subreddit/<int:sid>/posts/")
def get_subreddit_post(sid: int):
    """ Fetch the posts in this subreddit"""

    subreddit: Subreddit = Subreddit.query.filter_by(id=sid).first()
    if not subreddit:
        return failure_response("Subreddit not found")

    return success_response({"posts": subreddit.get_all_posts()})


@app.route("/api/users/<int:uid>/subreddit/<int:sid>/subscribe/", methods=["POST"])
def subscribe(uid: int, sid: int):
    """ Subscribes the user to a subreddit.
        No change is made if subscription was already made

        Requires Authentication
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    subreddit: Subreddit = Subreddit.query.filter_by(id=sid).first()
    if not subreddit:
        return failure_response("Subreddit not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    user.subscribe(subreddit)
    db.session.commit()

    return success_response(subreddit.serialize(), 201)


@app.route("/api/users/<int:uid>/subreddit/<int:sid>/unsubscribe/", methods=["POST"])
def unsubscribe(uid: int, sid: int):
    """ Unsubscribes a user from a subreddit
        No change is made if there was no prior subscription

        Requires Authentication
    """

    user: User = User.query.filter_by(id=uid).first()
    if not user:
        return failure_response("User not found")

    subreddit: Subreddit = Subreddit.query.filter_by(id=sid).first()
    if not subreddit:
        return failure_response("Subreddit not found")

    # Token verification
    success, message = verify_token(user.id, request)
    if not success:
        return message

    user.unsubscribe(subreddit)
    db.session.commit()

    return success_response(subreddit.serialize(), 201)


# @app.route("/api/testing/")
def testing():
    """Testing stuff"""

    subreddit: Subreddit = Subreddit(
        "Testing subs",
        "",
        "",
        "This sub has no about",
        [
            "All messages must be written in reverse order. The more confusing, the better!",
            "Only emacs allowed",
            "Only vi allowed"
        ]
    )

    db.session.add(subreddit)
    db.session.commit()

    return success_response(subreddit.serialize(), 201)


if __name__ == "__main__":
    # app.run(host="0.0.0.0", port=8000, debug=True)
    serve(app, host="127.0.0.1", port=8080)
