from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import hashlib
import re
import random
import base64
from PIL import Image
import string
from io import BytesIO
import boto3
from mimetypes import guess_extension, guess_type
from datetime import datetime
from dotenv import load_dotenv

# ==========================Constants===================================

USER_TABLE_NAME = "users"
POST_TABLE_NAME = "posts"
ASSET_TABLE_NAME = "images"
TOKEN_TABLE_NAME = "tokens"
COMMENT_TABLE_NAME = "comments"
SUBREDDIT_TABLE_NAME = "subreddits"

# ========================================================================


# ============================ Asset stuff========================================
load_dotenv()
EXTENSIONS = ["jpg", "png", "gif", "jpeg"]
S3_BUCKET_NAME: str = os.getenv("S3_BUCKET_NAME", "")
S3_BASE_URL: str = f"https://{S3_BUCKET_NAME}.s3.us-east-1.amazonaws.com"
BASE_DIR: str = os.getcwd()
DEFAULT_PICTURE_URL: str = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/defaultpicture.jpeg"
# ==========================================================================================


db = SQLAlchemy()

users_comments_upvotes = db.Table(
    "users_comments_upvotes",
    db.Column("user_id", db.Integer, db.ForeignKey(
        f"{USER_TABLE_NAME}.id")),
    db.Column("comment_id", db.Integer, db.ForeignKey(
        f"{COMMENT_TABLE_NAME}.id"))
)

users_comments_downvotes = db.Table(
    "users_comments_downvotes",
    db.Column("user_id", db.Integer, db.ForeignKey(
        f"{USER_TABLE_NAME}.id")),
    db.Column("comment_id", db.Integer, db.ForeignKey(
        f"{COMMENT_TABLE_NAME}.id"))
)

users_posts_upvotes = db.Table(
    "users_posts_upvotes",
    db.Column("user_id", db.Integer, db.ForeignKey(
        f"{USER_TABLE_NAME}.id"
    )),
    db.Column("post_id", db.Integer, db.ForeignKey(
        f"{POST_TABLE_NAME}.id"
    ))
)

users_posts_downvotes = db.Table(
    "users_posts_downvotes",
    db.Column("user_id", db.Integer, db.ForeignKey(
        f"{USER_TABLE_NAME}.id"
    )),
    db.Column("post_id", db.Integer, db.ForeignKey(
        f"{POST_TABLE_NAME}.id"
    ))
)

users_subreddits_subscriptions = db.Table(
    "users_subreddits_subscriptions",
    db.Column("user_id", db.Integer, db.ForeignKey(
        f"{USER_TABLE_NAME}.id"
    )),
    db.Column("subreddit_id", db.Integer, db.ForeignKey(
        f"{SUBREDDIT_TABLE_NAME}.id"
    ))
)


class Token(db.Model):
    """ Table to handle authorization tokens"""

    __tablename__ = TOKEN_TABLE_NAME
    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id: int = db.Column(
        db.Integer, db.ForeignKey(f"{TOKEN_TABLE_NAME}.id"), nullable=False)
    value: str = db.Column(db.String, nullable=False)
    created_at: int = db.Column(db.Integer, nullable=False)
    expires_at: int = db.Column(db.Integer, nullable=False)

    def __init__(self, user_id: int):
        """ Create a new session token for a given user id. Tokens expire after 1 day"""

        self.user_id = user_id
        self.value = self._maketoken()
        self.created_at = int(datetime.now().timestamp())
        self.expires_at = int((datetime.now() + timedelta(days=1)).timestamp())

    def _maketoken(self):
        """Produce a token value"""

        return hashlib.sha256(os.urandom(64)).hexdigest()

    def extend_token(self, user_id):
        """
            Extends the expiration of this token by 1 day for given userid.
            Will not be renewed if the token cannot be verified.

            Returns True if renewal is successful
        """

        if not self.verify(user_id):
            return False

        self.expires_at = int((datetime.now() + timedelta(days=1)).timestamp())

        return True

    def verify(self, user_id: int):
        """ Returns True if this token is valid for given user id"""
        return self.user_id == user_id and (self.expires_at > datetime.now().timestamp())

    def serialize(self):
        """ Returns a python dictionary representation of this token"""
        return {
            "id": self.id,
            "userId": self.user_id,
            "token": self.value,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at
        }


class Asset(db.Model):
    """ Table to handle image uploads"""

    __tablename__ = ASSET_TABLE_NAME
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    base_url = db.Column(db.String, nullable=False)
    salt = db.Column(db.String, nullable=False)
    extension = db.Column(db.String, nullable=False)
    width = db.Column(db.Integer, nullable=False)
    height = db.Column(db.Integer, nullable=False)

    @classmethod
    def create_salt(cls):
        """ Create a randomised 16 length string"""
        return "".join(
            random.SystemRandom().choice(
                string.ascii_uppercase + string.digits
            )
            for _ in range(16)
        )

    def get_extension(self, data: str):
        """Get the extension of an encoded image.

            Raises an exception if extension is not supported
        """
        guessed_type = guess_type(data)[0]
        extension = ""

        if guessed_type:
            guessed_extension = guess_extension(guessed_type)

            extension = guessed_extension[1:] if guessed_extension else ""
            # filter unsupported image types
            if extension not in EXTENSIONS:
                raise Exception(f"{extension} not supported!")

        return extension

    @classmethod
    def process(cls, data: str):
        """
            Attempt to process the image data into a `PIL.Image` object

            Throws an exception if unsuccessful.
        """

        try:
            temp_str = re.sub("data:image/.+;base64", "", data)

            # Decode
            decoded = base64.b64decode(temp_str)

            # Generate the image object
            img = Image.open(BytesIO(decoded))

            return img

        except Exception as e:
            print("\n******************************************************************")
            print(
                f"Exception during image data processing. Exception is as follows;\n{e}")
            print("******************************************************************\n")

    def __init__(self, image_data: str, extension: str | None = None):
        """ Create an Asset instance with the given extension.

            Uses default extensions if none is provided
        """

        self.base_url = S3_BASE_URL
        self.salt = self.create_salt()
        self.extension = self.get_extension(
            image_data) if extension == None else extension

        img = self.process(image_data)
        if img:
            self.width = img.width
            self.height = img.height

            self.upload(img)

    def upload(self, img: Image.Image):
        """Attempt to upload an image to Amazaon S3 bucket.

            Raises an Exception if unsuccessful
        """

        img_filename = f"{self.salt}.{self.extension}"

        try:
            # temporary save
            temp_location = f"{BASE_DIR}/{img_filename}"
            img.save(temp_location)

            # upload to aws
            aws_key: str = os.getenv("AWS_ACCESS_KEY_ID", "")
            s3_client = boto3.client("s3")
            s3_client.upload_file(temp_location, S3_BUCKET_NAME, img_filename)

            # make image public
            s3_resource = boto3.resource("s3")
            object_acl = s3_resource.ObjectAcl(  # type: ignore
                S3_BUCKET_NAME, img_filename)
            object_acl.put(ACL="public-read")

            # delete temporary save
            os.remove(temp_location)

        except Exception as e:
            print("\n******************************************************************")
            print(
                f'Exception during image upload. Exception as follows; \n {e}')
            print("******************************************************************\n")

    def serialize(self):
        """Return a python dictionary view of this asset"""
        return {
            "url": f'{self.base_url}/{self.salt}.{self.extension}'
        }


class Post(db.Model):
    """ Table for the posts"""

    __tablename__ = POST_TABLE_NAME

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id: int = db.Column(
        db.Integer, db.ForeignKey(f"{USER_TABLE_NAME}.id"), nullable=False)
    subreddit_id: int = db.Column(
        db.Integer, db.ForeignKey(f"{SUBREDDIT_TABLE_NAME}.id"), default=0)
    title: str = db.Column(db.String, nullable=False)
    contents: str = db.Column(db.Text, nullable=True)
    image_present: bool = db.Column(db.Boolean, nullable=True)
    image_url: str = db.Column(db.String, nullable=True)
    votes: int = db.Column(db.Integer, default=0)
    created_at: int = db.Column(db.Integer, nullable=False)
    comments: list["Comment"] = db.relationship("Comment", cascade="delete")

    upvoting_users: list["User"] = db.relationship(
        "User", secondary=users_posts_upvotes, back_populates="upvoted_posts"
    )
    downvoting_users: list["User"] = db.relationship(
        "User", secondary=users_posts_downvotes, back_populates="downvoted_posts"
    )

    def __init__(self, user_id: int, subreddit_id: int | None, title: str, 
                 contents: str = "", image_present: bool = False, 
                 image_url: str = ""):
        """
            Create a new post. The created_at and votes fields are automatically set. Votes is set to 1
        """
        self.user_id = user_id
        if subreddit_id != None:
            self.subreddit_id = subreddit_id
        self.title = title
        self.contents = contents
        self.image_present = image_present
        self.image_url = image_url
        self.created_at = int(datetime.now().timestamp())

    def serialize(self):
        """ Returns a simplified python dictionary view of this Post"""
        return {
            "id": self.id,
            "user": User.query.filter_by(id=self.user_id).first().serialize(),
            "subreddit": Subreddit.query.filter_by(id=self.subreddit_id).first().serialize(),
            "title": self.title,
            "contents": self.contents,
            "imagePresent": self.image_present,
            "imageURL": self.image_url,
            "createdAt": self.created_at,
            "votes": self.votes,
            "commentNumber": len(self.comments),
        }

    def full_serialze(self):
        """ Returns a full python dictionary view of this Post"""
        return {
            "id": self.id,
            "user": User.query.filter_by(id=self.user_id).first().serialize(),
            "subredditId": Subreddit.query.filter_by(id=self.subreddit_id).first().serialize(),
            "title": self.title,
            "contents": self.contents,
            "imagePresent": self.image_present,
            "imageURL": self.image_url,
            "createdAt": self.created_at,
            "votes": self.votes,
            "commentNumber": len(self.comments),
            "comments": [c.serialize() for c in self.comments],
        }

    def upvote(self):
        """ Upvote this post by 1 vote,
        """

        self.votes += 1

    def downvote(self):
        """
            Downvote this post by 1 vote,
            committing the changes to the database
        """

        self.votes -= 1

    def get_all_comments(self):
        """ Returns a list of all comments under this post. 

            Replies are returned under their parent comments.
        """

        return [c.full_serialize() for c in self.comments if c.ancestor_id < 1]


class Comment(db.Model):
    """ Table for comments"""

    __tablename__ = COMMENT_TABLE_NAME
    id: int = db.Column(db.Integer, autoincrement=True, primary_key=True)
    contents: str = db.Column(db.Text)
    user_id: int = db.Column(db.Integer, db.ForeignKey(
        f"{USER_TABLE_NAME}.id"), nullable=False)
    post_id: int = db.Column(db.Integer, db.ForeignKey(
        f"{POST_TABLE_NAME}.id"), nullable=False)
    created_at: int = db.Column(db.Integer, default=0)
    ancestor_id: int = db.Column(db.Integer, db.ForeignKey(
        f"{COMMENT_TABLE_NAME}.id"), default=-1)
    replies: list["Comment"] = db.relationship(
        "Comment", cascade="delete")

    votes: int = db.Column(db.Integer, default=0)
    upvoting_users: list["User"] = db.relationship(
        "User", secondary=users_comments_upvotes, back_populates="upvoted_comments")
    downvoting_users: list["User"] = db.relationship(
        "User", secondary=users_comments_downvotes, back_populates="downvoted_comments")

    def __init__(self, user_id: int, post_id: int, ancestor_id: int | None, contents: str):
        """ Create a new Comment"""

        self.user_id = user_id
        self.post_id = post_id
        self.contents = contents

        self.created_at = int(datetime.now().timestamp())

        if ancestor_id:
            self.ancestor_id = ancestor_id

    def serialize(self):
        """ Returns a simple python dictionary view of this comment"""

        return {
            "id": self.id,
            "user": User.query.filter_by(id=self.user_id).first().serialize(),
            "postId": self.post_id,
            "contents": self.contents,
            "votes": self.votes,
            "createdAt": self.created_at,
            "ancestorId": self.ancestor_id,
            "replyNumber": len(self.replies)

        }

    def full_serialize(self):
        """ Returns a full python dictionary view of this comment"""

        return {
            "id": self.id,
            "user": User.query.filter_by(id=self.user_id).first().serialize(),
            "postId": self.post_id,
            "contents": self.contents,
            "votes": self.votes,
            "createdAt": self.created_at,
            "ancestorId": self.ancestor_id,
            "replies": [r.full_serialize() for r in self.replies]

        }

    def upvote(self):
        """ Upvote this post by 1 vote
        """

        self.votes += 1

    def downvote(self):
        """
            Downvote this post by 1 vote
        """

        self.votes -= 1


class Subreddit(db.Model):
    """ Table representing subreddits"""

    __tablename__ = SUBREDDIT_TABLE_NAME
    id: int = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name: str = db.Column(db.String, nullable=False)
    imageURL: str = db.Column(db.String, nullable=False)
    thumbnail: str = db.Column(db.String, nullable=False)
    about: str = db.Column(db.Text, nullable=False)
    _rules: str = db.Column(db.Text)
    subcribers: list["User"] = db.relationship(
        "User", secondary=users_subreddits_subscriptions, back_populates="subscriptions"
    )
    posts: list[Post] = db.relationship("Post")

    def _process_rules_to_string(self, rules: list[str]):
        """
            Processes and returns a list of string rules into 
            a single string for storage
        """
        return ":;".join(rules)

    def _process_string_to_rules(self):
        """ Processes and returns the rules string into a list
            of strings.
        """
        return self._rules.split(":;")

    def __init__(self, name: str, image_url: str, thumbnail_url: str, about: str, rules: list[str]):
        """ Create a new subreddit"""

        self.name = name
        self.imageURL = image_url
        self.thumbnail = thumbnail_url
        self.about = about
        self._rules = self._process_rules_to_string(rules)

    def serialize(self):
        """ Returns a simple python dictionary view of this subreddit"""

        return {
            "id": self.id,
            "name": self.name,
            "about": self.about,
            "imageURL": self.imageURL,
            "thumbnailURL": self.thumbnail,
            "subscriberNumber": len(self.subcribers),
            "rules": self._process_string_to_rules()
        }

    def full_serialize(self):
        """ Returns a full python dictionary view of this subreddit"""

        return {
            "id": self.id,
            "name": self.name,
            "about": self.about,
            "imageURL": self.imageURL,
            "thumbnailURL": self.thumbnail,
            "subscriberNumber": len(self.subcribers),
            "rules": self._process_string_to_rules(),
            "posts": self.get_all_posts()
        }

    def get_all_posts(self):
        """ Returns a list of all Posts in this subreddit"""

        return [p.serialize() for p in self.posts]

    def get_subscribers(self):
        """ Returns a list of all Users subscribed to this subreddit"""

        return [u.serialize() for u in self.subcribers]


class User(db.Model):
    """ Table representing users"""

    __tablename__ = USER_TABLE_NAME
    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username: str = db.Column(db.String, nullable=False)
    image_url: str = db.Column(db.String, nullable=False)
    email: str = db.Column(db.String, nullable=False)
    karma: int = db.Column(db.Integer, default=0)
    joined: int = db.Column(db.Integer, nullable=False)
    _passoword: str = db.Column(db.String, nullable=False)
    posts: list["Post"] = db.relationship("Post", cascade="delete")

    # Posts
    upvoted_posts: list["Post"] = db.relationship(
        "Post", secondary=users_posts_upvotes, back_populates="upvoting_users"
    )
    downvoted_posts: list["Post"] = db.relationship(
        "Post", secondary=users_posts_downvotes, back_populates="downvoting_users"
    )

    # Comments
    comments: list["Comment"] = db.relationship("Comment", cascade="delete")
    upvoted_comments: list["Comment"] = db.relationship(
        "Comment", secondary=users_comments_upvotes, back_populates="upvoting_users")
    downvoted_comments: list["Comment"] = db.relationship(
        "Comment", secondary=users_comments_downvotes, back_populates="downvoting_users")

    # Subreddits
    subscriptions: list[Subreddit] = db.relationship(
        "Subreddit", secondary=users_subreddits_subscriptions, back_populates="subcribers"
    )

    @classmethod
    def _process_password(cls, password: str):
        """
            Returns a salted and hashed version of `password`
        """
        presalt: str = os.getenv("PRESALT", "")
        postsalt: str = os.getenv("POSTSALT", "")

        salted = postsalt + password + presalt
        hash = hashlib.sha256()
        hash.update(salted.encode("utf-8"))

        return hash.hexdigest()

    def __init__(self, username: str, email: str, password: str, image_url: str = ""):
        """Create a new User instance. The id, karma and joindate
          are generated automatically. The password provided is salted and hashed
          before being stored.

          If no imageURL is provided, a default is provided"""

        self.username = username
        self.email = email
        self.image_url = image_url if image_url else DEFAULT_PICTURE_URL
        self.joined = int(datetime.now().timestamp())
        self._passoword = self._process_password(password)

    def serialize(self):
        """ Return a simplified dictionary view of this User"""
        return {
            "id": self.id,
            "username": self.username,
            "imageURL": self.image_url,
            "karma": self.karma,
            "joined": self.joined
        }

    def full_serialize(self):
        """ Return a full dictionary view of this User"""
        return {
            "id": self.id,
            "username": self.username,
            "imageURL": self.image_url,
            "karma": self.karma,
            "joined": self.joined,
            "email": self.email,
            "posts": self.get_all_posts(),
            "upvotedPosts": self.get_upvoted_posts(),
            "downvotedPosts": self.get_downvoted_posts(),
            "comments": self.get_all_comments(),
            "upvotedComments": self.get_upvoted_comments(),
            "downvotedComments": self.get_downvoted_comments(),
            "subreddits": self.get_subscriptions(),
        }

    def hash_and_verify(self, password: str):
        """ Returns True if `password` matches the stored password of this user"""

        # password
        password = self._process_password(password)

        return self._passoword == password

    def verify(self, password: str):
        """ Checks if this `password` is the password of this user"""
        return self._passoword == password

    def update_username(self, new_username: str):
        """ Updates the username of this instance to `new_username` and commits to 
        the database."""

        self.username = new_username

    def update_image_url(self, new_url: str):
        """
            Updates the image url of this user and commits the changes to the 
            database.
        """

        self.image_url = new_url

    def update_password(self, new_password: str):
        """
            Updates the password of this user, commiting the changes to the database

        """

        self._passoword = self._process_password(new_password)

    def update_email(self, new_email: str):
        """ Updates the email of this user, committing the changes to the
            database
        """
        self.email = new_email

    def increase_karma(self, amount: int):
        """ Increases the karma of this user by `amount`, committing
            the changes
        """

        self.karma += amount

    # Posts
    def get_upvoted_posts(self):
        """ Returns a list of all upvoted posts"""

        return [p.serialize() for p in self.upvoted_posts]

    def get_downvoted_posts(self):
        """ Returns a list of post ids of all downvoted posts"""

        return [p.serialize() for p in self.downvoted_posts]

    def upvote_post(self, post: Post):
        """ Upvotes a post. Posts can only be upvoted once

            If post was previously downvoted, the downvote is removed
            and an upvote is added.

            The post's votes is updated accordingly
        """

        if post in self.upvoted_posts:
            return

        if post in self.downvoted_posts:
            self.downvoted_posts.remove(post)
            post.upvote()

        self.upvoted_posts.append(post)
        post.upvote()

    def downvote_post(self, post: Post):
        """ Downvotes a post. Posts can only be downvoted once.

            If post was previously upvoted, the upvote is removed
            and an downvote is added.


            The post's votes is updated accordingly
        """

        if post in self.downvoted_posts:
            return

        if post in self.upvoted_posts:
            self.upvoted_posts.remove(post)
            post.downvote()

        self.downvoted_posts.append(post)
        post.downvote()

    def reset_post_vote(self, post: Post):
        """
            Removes post from this user's upvotes and downvotes,
            updating the post's vote while doing so
        """

        if post in self.upvoted_posts:
            self.upvoted_posts.remove(post)
            post.downvote()

        if post in self.downvoted_posts:
            self.downvoted_posts.remove(post)
            post.upvote()

    def get_all_posts(self):
        """ Returns a list of the posts of this user"""

        return [p.serialize() for p in self.posts]

    # Comments
    def upvote_comment(self, comment: Comment):
        """ Upvotes a comment. Comments can only be upvoted once

            If comment was previously downvoted, the downvote is removed
            and an upvote is added

            The comment's votes is updated accordingly
        """

        if comment in self.upvoted_comments:
            return

        if comment in self.downvoted_comments:
            self.downvoted_comments.remove(comment)
            comment.upvote()

        self.upvoted_comments.append(comment)
        comment.upvote()

    def downvote_comment(self, comment: Comment):
        """ Downvotes a comment. Comments can only be downvoted once

            If comment was previously upvoted, the upvote is removed
            and an downvote is added.

            The comment's votes is updated accordingly
        """

        if comment in self.downvoted_comments:
            return

        if comment in self.upvoted_comments:
            self.upvoted_comments.remove(comment)
            comment.downvote()

        self.downvoted_comments.append(comment)
        comment.downvote()

    def reset_comment_vote(self, comment: Comment):
        """
            Removes comment from this user's upvotes and downvotes,
            updating the comment's vote while doing so
        """

        if comment in self.upvoted_comments:
            self.upvoted_comments.remove(comment)
            comment.downvote()

        if comment in self.downvoted_comments:
            self.downvoted_comments.remove(comment)
            comment.upvote()

    def get_all_comments(self):
        """
            Returns a list of all comments left by this user
        """

        return [c.serialize() for c in self.comments]

    def get_upvoted_comments(self):
        """Returns a list of all comments upvoted by this user"""

        return [c.serialize() for c in self.upvoted_comments]

    def get_downvoted_comments(self):
        """Returns a list of all comments downvoted by this user"""
        return [c.serialize() for c in self.downvoted_comments]

    # Subreddits
    def get_subscriptions(self):
        """ Returns a list of all subreddits this user has subscribed to."""

        return [s.serialize() for s in self.subscriptions]

    def subscribe(self, subreddit: Subreddit):
        """ Subscribes this user to `subreddit`

            Nothing is changed if the user was already subscribed.
        """

        if subreddit in self.subscriptions:
            return

        self.subscriptions.append(subreddit)

    def unsubscribe(self, subreddit: Subreddit):
        """ Unsubscribes this suer from `subreddit`.

            Nothing is changed if the user was not subscribed.
        """

        if not subreddit in self.subscriptions:
            return

        self.subscriptions.remove(subreddit)
