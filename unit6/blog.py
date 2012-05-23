import os
import re
import random
import string
import hashlib
import webapp2
import jinja2
import json
import logging
import time
import datetime
import calendar
from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache

logging.getLogger().setLevel(logging.DEBUG)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

lastupdate = time.time()

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### blog stuff

# return json string for inidividual post
def blog_post_json(post):
    js = {}
    js['content'] = post.content
    js['created'] = post.created.strftime("%a %b %d %H:%M:%S %Y")
    js['last_modified'] = post.last_modified.strftime("%a %b %d %H:%M:%S %Y")
    js['subject'] = post.subject
    return js

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
# Add caching here
        global lastupdate
        posts = memcache.get("front")
        if posts is not None:
            self.render('front.html', 
                        posts = posts, 
                        seconds = int((time.time() - lastupdate)))
        else:
            posts = db.GqlQuery("select * from Post order by created desc limit 10")
            memcache.add("front", posts)
            self.render('front.html', 
                        posts = posts, seconds = 0)            
            lastupdate = time.time()


class BlogFrontJSON(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        post_json = []
        for p in posts:
            post_json.append(blog_post_json(p))

        if len(post_json):
            self.response.headers.add_header("Content-Type", "application/json")
            self.response.out.write(json.dumps(post_json, sort_keys=True))

class PostPage(BlogHandler):
    def get(self, post_id):
        logging.debug("checking cache...")
        post = memcache.get(repr(post_id))
        if post is not None:
            logging.debug("found in cache...")
            seconds = int(
                (time.time() - 
                 calendar.timegm(post.last_modified.utctimetuple())))
            self.render("permalink.html", post = post, seconds = seconds)
        else:
            # Cache may have been flushed, need to repopulate
            logging.debug("not found in cache...")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            post.last_modified = datetime.datetime.now()
            logging.debug("adding %s to cache...", repr(post_id))
            memcache.add(repr(post_id), post)
            self.render("permalink.html", post = post, seconds = 0)

# Permalink Page output in JSON
class PostPageJSON(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.response.headers.add_header("Content-Type", "application/json")
        self.response.out.write(json.dumps(blog_post_json(post), sort_keys=True))

class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            # add to cache
            logging.debug("adding new post %s to cache...", repr(p.key().id()))
            memcache.add(repr(p.key().id()), p)
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)



###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


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



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

def valid_verify(s, p):
    if (s == p):
        return PASS_RE.match(p)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.redirect('/unit2/welcome?username=' + username)

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')


class SignupHandler(BlogHandler):

    def render_signup(self, username="", nameerror="", passworderror="", verifyerror="",
		      email="", emailerror=""):
	    self.render("blog-signup-form.html", username=username, nameerror=nameerror,
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

        name     = valid_username(user_name)
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

class LoginHandler(BlogHandler):

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

class LogoutHandler(BlogHandler):

    def get(self):
            self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
            self.redirect("/blog/signup")            

class HomeHandler(BlogHandler):

    # given user_id cookie, extract user_id
    def get_user_id_from_cookie(self, cookie):
	    return  cookie.split('|')[0]

    def get(self):
	cookie = self.request.cookies.get('user_id')
	user_id = self.get_user_id_from_cookie(cookie)
	u = User.get_by_id(int(user_id))
        self.response.out.write("Welcome %s!"%u.username)

class FlushHandler(BlogHandler):

    def get(self):
        # Flush the entire cache
        memcache.flush_all()
        self.redirect("/blog")
        

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/.json', BlogFrontJSON),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/([0-9]+).json', PostPageJSON),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', SignupHandler),
                               ('/blog/login',  LoginHandler),
                               ('/blog/logout',  LogoutHandler),
                               ('/blog/welcome', HomeHandler),
                               ('/blog/flush', FlushHandler),
                               ],
                              debug=True)
