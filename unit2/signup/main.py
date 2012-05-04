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
import webapp2
import cgi
import re
import logging

form="""
<form method="post">
  <h2>Signup</h2>
  <br>
  <label> Username
     <input type="textarea" name="username" value="%(username)s">
     <b style="color: red">%(nameerror)s</b>
  </label>
  <br>
  <label> Password
     <input type="password" name="password">
     <b style="color: red">%(passworderror)s</b>
  </label>
  <br>
  <label> Verify Password
     <input type="password" name="verify">
     <b style="color: red">%(verifyerror)s</b>
  </label>
  <br>
  <label> Email (optional)
     <input type="textarea" name="email" value="%(email)s">
     <b style="color: red">%(emailerror)s</b>
  </label>
  <br>
  <br>
  <input type="submit">
</form>
"""

USER_RE  = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE  = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_name(s):
        return USER_RE.match(s)

def valid_password(s):
        return PASS_RE.match(s)

def valid_verify(s, p):
    if (s == p):
        return PASS_RE.match(p)

def valid_email(s):
        return EMAIL_RE.match(s)

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Sorry, nothing to see here!")

class SignupHandler(webapp2.RequestHandler):

    def write_form(self, username="", nameerror="", passworderror="", verifyerror="",
                   email="", emailerror=""):
        self.response.out.write(form % {"username": cgi.escape(username),
                                        "nameerror": nameerror,
                                        "passworderror": cgi.escape(passworderror),
                                        "verifyerror": cgi.escape(verifyerror),
                                        "email": cgi.escape(email),
                                        "emailerror": cgi.escape(emailerror)})

    def get(self):
        self.write_form()

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

#        logging.debug("name %s pass %s verify %s email %s", name, password, verify, email)

        if (not (name and password and verify)) or (user_email and not email):
            self.write_form(user_name, nameerror, passworderror, 
                            verifyerror, user_email, emailerror)
        else:
            self.redirect("/unit2/welcome?username=%s"%user_name)

class HomeHandler(webapp2.RequestHandler):
    def get(self):
        name = self.request.get("username")
        self.response.out.write("Welcome %s!"%name)

app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/unit2/signup', SignupHandler),
                               ('/unit2/welcome', HomeHandler)
                              ], debug=True)
