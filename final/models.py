from google.appengine.ext import db

# User model for google datastore
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created  = db.DateTimeProperty(auto_now_add = True)

def get_user_by_name(user_name):
    return User.gql("WHERE username = '%s'"%user_name).get()


