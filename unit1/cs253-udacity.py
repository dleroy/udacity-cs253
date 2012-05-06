from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

form="""
<form method="post">
  What is your birthday?
  <br>
  <label> Month
     <input type="text" name="month">
  </label>
  <label> Day
  <input type="text" name="day">
  </label>
  <label> Year
  <input type="text" name="year">
  </label>
  <br>
  <br>
  <input type="submit">
</form>
"""
class MainPage(webapp.RequestHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write(form)

#class TestHandler(webapp.RequestHandler):
    def post(self):
        #q = self.request.get("q")
        self.response.out.write("Thanks. That's a totally valid day!")

#        self.response.headers['Content-Type'] = 'text/plain'
#        self.response.out.write(self.request)

application = webapp.WSGIApplication([('/', MainPage)], debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()

