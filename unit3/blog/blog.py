import os
import re
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Post model for google db
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class PostPermalink(Handler):

    def render_post(self, id):
        p = Post.get_by_id(int(id))
        self.render("post.html", post=p)

    def get(self, post_id):
        self.render_post(post_id)

class PostForm(Handler):

    # redirect to blog entry permalink. If entry not specified (0)
    def redirect_permalink(self, id=0):
        if id == 0:
            self.redirect("/blog/newpost")
        else:
            self.redirect("/blog/" + str(id))
    
    def render_main(self, subject="", content="", error=""):
        posts = db.GqlQuery("select * from Post order by created DESC")

        self.render("post-form.html", subject=subject, 
                    content=content, error=error, posts=posts)

    def get(self):
        self.render_main()
    
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            p = Post(subject = subject, content = content)
            p.put()
            id = p.key().id()
            self.redirect_permalink(id)

        else:
            error = "we need both a subject and content!"
            self.render_main(subject, content, error)


class MainPage(Handler):

    def render_main(self):
        posts = db.GqlQuery("select * from Post order by created DESC")

        self.render("mainpage.html", posts=posts)

    def get(self):
        self.render_main()

app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/newpost', PostForm),
                               (r'/blog/(\d+)', PostPermalink),
                               ], debug=True)
