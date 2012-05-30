# Utilities
import re
import string
import random
import hashlib
import logging
from models import User

# Valid username
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

# Valid password
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

# Valid verify password
def valid_verify(s, p):
    if (s == p):
        return PASS_RE.match(p)

# Valid email
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


# routines for hashing passwords with salt
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

# given user_id cookie, extract user_id
def get_user_id_from_cookie(cookie):
    return  cookie.split('|')[0]

# given user_id cookie, extract user_id
def get_hash_from_cookie(cookie):
    return  cookie.split('|')[1]

# given user_id cookie, extract user_id
def get_hash_from_password(password):
    return  password.split('|')[0]

# given user cookie, return username. If no cookie exists, return None
def get_username_from_cookie(cookie):
    username = None
    if cookie:
        user_id = get_user_id_from_cookie(cookie)
        u = User.get_by_id(int(user_id))
        if get_hash_from_cookie(cookie) == get_hash_from_password(u.password):
            username = u.username
    return username

