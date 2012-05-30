import os
import re
import cgi
import webapp2
import jinja2
import logging
import utils
import models
from models import User
from google.appengine.ext import db

# Set log level to debug
logging.getLogger().setLevel(logging.ERROR)

# Initialize jinja templating environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# Wiki page model for google datastore
class Wiki(db.Model):
    urlpath = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

def wiki_key(name = 'default'):
    return db.Key.from_path('wikis', name)

def get_wikipage_by_path(pagepath):
    return Wiki.gql("WHERE urlpath = '%s'"%pagepath).get()

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Signup(WikiHandler):

    def render_signup(self, 
                      username="", 
                      nameerror="", 
                      passworderror="", 
                      verifyerror="",
		      email="", 
                      emailerror=""):
        self.render("wiki-signup-form.html", 
                    username=username, 
                    nameerror=nameerror,
                    passworderror=passworderror, 
                    verifyerror=verifyerror,
                    email=email, 
                    emailerror=emailerror)

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

        name     = utils.valid_username(user_name)
        password = utils.valid_password(user_password)
        verify   = utils.valid_verify(user_verify, user_password)
        email    = utils.valid_email(user_email)

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
                h = utils.make_pw_hash(user_name, user_password)
                u = User(username=user_name, password=h)
                u.put()
                user_id = u.key().id()
                uid_cookie = str(self.put_user_id_cookie(user_id, h))
                self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/"%uid_cookie)
                self.redirect("/")

class Login(WikiHandler):

    def render_login(self, username="", error=""):
        self.render("wiki-login-form.html", username=username, error=error)

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
        u = models.get_user_by_name(user_name)
        if not u or not utils.valid_pw(user_name, user_password, u.password):
           error = "Invalid login"
           self.render_login(user_name, error)
        else:
            user_id = u.key().id()
            uid_cookie = str(self.put_user_id_cookie(user_id, u.password))
            self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/"%uid_cookie)
            self.redirect("/")            


class Logout(WikiHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/")            

#
# We arrive here either because 1) a user is logged in and clicked on the edit link for a page or 2) someone directly
# typed in the _edit link but is not logged in.
# We validate the user is logged in and if so we display the edit page, otherwise redirect to the wiki page.
# we take the new content entered in the post form and update the page contents.
#
class EditPage(WikiHandler):

    def get(self, pagepath):
	cookie = self.request.cookies.get('user_id')
        # Look up pagepath for existing page. If exists set pagetext to contents, else pagetext = None
        username = utils.get_username_from_cookie(cookie)
        logging.error("editpage get, username %s  pagepage %s\n", username, pagepath)
        if username:
            mywikipage = get_wikipage_by_path(pagepath)
            if mywikipage:
                content = mywikipage.content
            else:
                content = ""

            logging.error("content is %s\n", content)
            self.render("editpage.html", 
                        user = utils.get_username_from_cookie(cookie), 
                        editurl = None, 
                        content = content)

    def post(self, pagepath):
	cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        logging.error("In edit page post: pagepath %s username %s\ncookie %s\n",
                      pagepath, username, cookie)
        logging.error("Pagepath now %s\n",  pagepath)
        if username:
            edited_content = self.request.get('content')
            logging.error("content = %s\n", edited_content)
            # see if this page already exists
            mywikipage = get_wikipage_by_path(pagepath)
            if edited_content and pagepath:
                if mywikipage:
                    # already existing page, just update content
                    mywikipage.content = edited_content
                else:
                    # create new wiki page
                    mywikipage = Wiki(parent = wiki_key(), 
                                      urlpath = pagepath,
                                      content = edited_content)
                # store new or modified page
                mywikipage.put()

        # redirect to the wiki page and display with updated contents
        logging.error("redirecting to = %s\n", pagepath)
        self.redirect(pagepath)

#
# Handler for all pages under wiki hierarchy. 
# we detect whether a user is currently logged in (get_username_from_cookie) and if so we display an edit page link.
# 
class WikiPage(WikiHandler):
    def get(self,pagepath):
	cookie = self.request.cookies.get('user_id')
        username = utils.get_username_from_cookie(cookie)
        logging.error("wikipage get, cookie %s  pagepath %s\n", cookie, pagepath)
        editurl = "/_edit" + pagepath
        mywikipage = get_wikipage_by_path(pagepath)
        # If page already exists in Wiki, retreive content and display
        if mywikipage:
            content = mywikipage.content
            self.render("wikipage.html", 
                        user = username,
                        editurl = editurl,
                        content = content)
        # If page doesn't exist, redirect to an edit page assuming user is logged in
        elif username:
            self.redirect(editurl)
        else:
            self.render("wikipage.html", 
                        user = username,
                        editurl = editurl,
                        content = "")

DEBUG = True
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=DEBUG)


