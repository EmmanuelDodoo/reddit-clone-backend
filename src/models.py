from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import hashlib
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
import json
import re
import random
import base64
from PIL import Image
import string
from io import BytesIO
import boto3
from mimetypes import guess_extension, guess_type
from datetime import datetime


db = SQLAlchemy()


EXTENSIONS = ["jpg", "png", "gif", "jpeg"]
S3_BUCKET_NAME: str = os.getenv("S3_BUCKET_NAME", "")
S3_BASE_URL: str = f"https://{S3_BUCKET_NAME}.s3.us-east-1.amazonaws.com"
BASE_DIR: str = os.getcwd()
DEFAULT_PICTURE_URL: str = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/defaultpicture.jpeg"


class User(db.Model):
    """ Table representing users"""

    __tablename__ = "users"
    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username: str = db.Column(db.String, nullable=False)
    image_url: str = db.Column(db.String, nullable=False)
    email: str = db.Column(db.String, nullable=False)
    karma: int = db.Column(db.Integer, default=0)
    joined: int = db.Column(db.Integer, nullable=False)
    _passoword: str = db.Column(db.String, nullable=False)
    posts = db.relationship("Post", cascade="delete")
    # a white space separated string of the post ids
    _posts_upvoted: str = db.Column(db.String, default="")
    _posts_downvoted: str = db.Column(db.String, default="")

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

    def __init__(self, username: str, email: str, password: str, imageURL: str = ""):
        """Create a new User instance. The id, karma and joindate
          are generated automatically. The password provided is salted and hashed
          before being stored.

          If no imageURL is provided, a default is provided"""

        self.username = username
        self.email = email
        self.image_url = imageURL if imageURL else DEFAULT_PICTURE_URL
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
            "upvoted_posts": self.get_upvoted_posts(),
            "downvoted_posts": self.get_downvoted_posts(),
            "posts": [p.serialize() for p in Post.query.filter_by(userid=self.id)]
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
        db.session.commit()

    def update_image_url(self, new_url: str):
        """
            Updates the image url of this user and commits the changes to the 
            database.
        """

        self.image_url = new_url
        db.session.commit()

    def update_password(self, new_password: str):
        """
            Updates the password of this user, commiting the changes to the database

        """

        self._passoword = self._process_password(new_password)
        db.session.commit()

    def update_email(self, new_email: str):
        """ Updates the email of this user, committing the changes to the
            database
        """
        self.email = new_email
        db.session.commit()

    def increase_karma(self, amount: int):
        """ Increases the karma of this user by `amount`, committing
            the changes
        """

        self.karma += amount
        db.session.commit()

    def get_upvoted_posts(self):
        """ Returns a list of post ids of all upvoted posts"""

        split = self._posts_upvoted.split()

        return [int(i) for i in split]

    def get_downvoted_posts(self):
        """ Returns a list of post ids of all downvoted posts"""

        split = self._posts_downvoted.split()

        return [int(i) for i in split]

    def add_post_upvote(self, post_id: int):
        """ Add the post with id, `post_id` to this user's upvotes,
            Committing the changes to the database.


            Requires: the post id is valid.
        """

        self._posts_upvoted += f" {post_id}"
        db.session.commit()

    def remove_post_upvote(self, post_id: int):
        """
            Remove the post with id, `post_id` from this user's upvotes,
            committing the changes to the database.

            Requires: the post id is valid.
        """

        self._posts_upvoted = self._posts_upvoted.replace(str(post_id), "")
        db.session.commit()

    def add_post_downvote(self, post_id: int):
        """ Add the post with id, `post_id` to this user's downvotes,
            Committing the changes to the database.


            Requires: the post id is valid.
        """

        self._posts_downvoted += f" {post_id}"
        db.session.commit()

    def remove_post_downvote(self, post_id: int):
        """
            Remove the post with id, `post_id` from this user's downvotes,
            committing the changes to the database.

            Requires: the post id is valid.
        """

        self._posts_downvoted = self._posts_downvoted.replace(str(post_id), "")
        db.session.commit()

    def get_all_posts(self):
        """ Returns all the posts of this user"""

        return {
            "posts": [p.serialize() for p in Post.query.filter_by(userid=self.id)]
        }


class Token(db.Model):
    """ Table to handle authorization tokens"""

    __tablename__ = "tokens"
    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userid: int = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    value: str = db.Column(db.String, nullable=False)
    created_at: int = db.Column(db.Integer, nullable=False)
    expires_at: int = db.Column(db.Integer, nullable=False)

    def __init__(self, userid: int):
        """ Create a new session token for a given user id. Tokens expire after 1 day"""

        self.userid = userid
        self.value = self._maketoken()
        self.created_at = int(datetime.now().timestamp())
        self.expires_at = int((datetime.now() + timedelta(days=1)).timestamp())

    def _maketoken(self):
        """Produce a token value"""

        return hashlib.sha256(os.urandom(64)).hexdigest()

    def extend_token(self, userid):
        """
            Extends the expiration of this token by 1 day for given userid.
            Will not be renewed if the token cannot be verified.

            Returns True if renewal is successful
        """

        if not self.verify(userid):
            return False

        self.expires_at = int((datetime.now() + timedelta(days=1)).timestamp())
        db.session.commit()

        return True

    def verify(self, userid: int):
        """ Checks i fthis token is valid for given user id"""
        return self.userid == userid and (self.expires_at > datetime.now().timestamp())

    def serialize(self):
        """ Returns a python dictionary representation of this token"""
        return {
            "id": self.id,
            "userid": self.userid,
            "token": self.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at
        }


class Asset(db.Model):
    """ Table to handle image uploads"""

    __tablename__ = "images"
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

    __tablename__ = "posts"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userid: int = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    title: str = db.Column(db.String, nullable=False)
    contents: str = db.Column(db.Text, nullable=True)
    image_present: bool = db.Column(db.Boolean, nullable=True)
    image_url: str = db.Column(db.String, nullable=True)
    votes: int = db.Column(db.Integer, default=1)
    created_at: int = db.Column(db.Integer, nullable=False)

    def __init__(self, userid: int, title: str, contents: str = "", image_present: bool = False, image_url: str = ""):
        """
            Create a new post. The created_at and votes fields are automatically set. Votes is set to 1
        """
        self.userid = userid
        self.title = title
        self.contents = contents
        self.image_present = image_present
        self.image_url = image_url
        self.created_at = int(datetime.now().timestamp())

    def serialize(self):
        """ Returns a simplified python dictionary view of this Post"""
        return {
            "id": self.id,
            "userid": self.userid,
            "title": self.title,
            "contents": self.contents,
            "imagePresent": self.image_present,
            "imageURL": self.image_url,
            "created_at": self.created_at,
            "votes": self.votes
        }

    def upvote(self):
        """ Upvote this post by 1 vote,
            Committing the changes to the database
        """

        self.votes += 1
        db.session.commit()

    def downvote(self):
        """
            Downvote this post by 1 vote,
            committing the changes to the database
        """

        self.votes -= 1
        db.session.commit()
