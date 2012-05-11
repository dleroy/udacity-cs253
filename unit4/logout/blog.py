#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import webapp2
import jinja2
from google.appengine.ext import db
import random
import string
import hashlib
import logging

# setup for jinja templating
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# User model for google db
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created  = db.DateTimeProperty(auto_now_add = True)

def get_user_by_name(user_name):
    return User.gql("WHERE username = '%s'"%user_name).get()

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


# functions for validating signup input
USER_RE  = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_name(s):
        return USER_RE.match(s)

PASS_RE  = re.compile(r"^.{3,20}$")
def valid_password(s):
        return PASS_RE.match(s)

def valid_verify(s, p):
    if (s == p):
        return PASS_RE.match(p)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(s):
        return EMAIL_RE.match(s)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class SignupHandler(Handler):

    def render_signup(self, username="", nameerror="", passworderror="", verifyerror="",
		      email="", emailerror=""):
	    self.render("signup-form.html", username=username, nameerror=nameerror,
			passworderror=passworderror, verifyerror=verifyerror,
			email=email, emailerror=emailerror)

    # given user_id and pwhash, create user_id cookie
    def put_user_id_cookie(self, user_id, pwhash):
	    hash = pwhash.split('|')[0]
	    return '%s|%s'%(user_id, hash)

    def get(self):
	    self.render_signup()

    def post(self):
        user_name     = self.request.get('username')
        user_password = self.request.get('password')
        user_verify   = self.request.get('verify')
        user_email    = self.request.get('email')

        name     = valid_name(user_name)
        password = valid_password(user_password)
        verify   = valid_verify(user_verify, user_password)
        email    = valid_email(user_email)

        nameerror = passworderror = verifyerror = emailerror = ""

        if not name:
            nameerror = "That's not a valid username"

        if not password:
            passworderror = "That's not a valid password"

        if password and not verify:
            verifyerror = "Your passwords didn't match"

        if user_email and not email:
            emailerror = "That's not a valid email"

        if (not (name and password and verify)) or (user_email and not email):
		self.render_signup(user_name, nameerror, passworderror, 
				   verifyerror, user_email, emailerror)
        else:
		# lookup user
		u = User.gql("WHERE username = '%s'"%user_name).get()

		# If user already exists
		if u:
			nameerror = "That user already exists"
			self.render_signup(user_name, nameerror, passworderror, 
					   verifyerror, user_email, emailerror)		
		else:
			# make salted password hash
			h = make_pw_hash(user_name, user_password)
			u = User(username=user_name, password=h)
			u.put()
			user_id = u.key().id()
			uid_cookie = str(self.put_user_id_cookie(user_id, h))
			self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/"%uid_cookie)
			self.redirect("/blog/welcome")


class LoginHandler(Handler):

    def render_login(self, username="", error=""):
        self.render("login-form.html", username=username, error=error)

    # given user_id and pwhash, create user_id cookie
    def put_user_id_cookie(self, user_id, pwhash):
	    hash = pwhash.split('|')[0]
	    return '%s|%s'%(user_id, hash)

    def get(self):
	    self.render_login()

    def post(self):
        user_name     = self.request.get('username')
        user_password = self.request.get('password')

        # Look up user
        u = get_user_by_name(user_name)
        if not u or not valid_pw(user_name, user_password, u.password):
           error = "Invalid login"
           self.render_login(user_name, error)
        else:
            user_id = u.key().id()
            uid_cookie = str(self.put_user_id_cookie(user_id, u.password))
            self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/"%uid_cookie)
            self.redirect("/blog/welcome")            

class LogoutHandler(Handler):

    def get(self):
            self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
            self.redirect("/blog/signup")            


class WelcomeHandler(Handler):

    # given user_id cookie, extract user_id
    def get_user_id_from_cookie(self, cookie):
	    return  cookie.split('|')[0]

    def get(self):
        error = False
	cookie = self.request.cookies.get('user_id')
        if len(cookie):
            user_id = self.get_user_id_from_cookie(cookie)
            if len(user_id):
                u = User.get_by_id(int(user_id))
                if u:
                    self.response.out.write("Welcome %s!"%u.username)
                else:
                    error = True
            else:
                error = True
        else:
            error = True

        if error:
            self.redirect("/blog/signup")

app = webapp2.WSGIApplication([('/blog/signup', SignupHandler),
                               ('/blog/login',  LoginHandler),
                               ('/blog/logout',  LogoutHandler),
                               ('/blog/welcome', WelcomeHandler),
                              ], debug=True)
