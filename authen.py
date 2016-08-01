import os
import jinja2
import webapp2
import hmac
import random
import string
import hashlib
import re

from models import User
# from authentification import SignupHandler, LoginHandler, LogoutHandler
from google.appengine.ext import db

# current dir /templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# jinja look for templates in template_dir
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def set_cookie(self, name, value):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header(
            'Set-Cookie', str('%s=%s; Path=/' % (name, value)))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('userId')
        self.user = uid and User.get_by_id(int(uid))


# signup page handler


class SignupHandler(Handler):

    def write_form(self, name="", password="", verify="", email="",
                   error_username="", error_password="", error_verify="",
                   error_email=""):
        self.render("signup.html", user=self.user, username=name,
                    password=password, verify=verify, email=email,
                    error_username=error_username,
                    error_password=error_password,
                    error_verify=error_verify, error_email=error_email)

    def get(self):
        self.write_form()

    def post(self):
        user_name = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        error_username = ''
        error_password = ''
        error_verify = ''
        error_email = ''

        # verufy all parameters
        if not(valid_username(user_name)):
            error_username = 'invalid username'
            user_name = ''
        if not(valid_password(user_password)):
            error_password = 'invalid password'
            user_password = ''
            user_verify = ''
        elif not(user_password == user_verify):
            error_verify = 'passwords not identical'
            user_password = ''
            user_verify = ''
        if user_email and not(valid_email(user_email)):
            error_email = 'invalid email'
            user_email = ''
        if is_existing_username(user_name):
            error_username = 'user already exist'
            user_name = ''

        if not(error_username or error_email or error_verify or
               error_password):
            # if no error, create new user account
            u = User(username=user_name, password=make_pw_hash(
                user_name, user_password), email=user_email)
            u.put()
            self.set_cookie('userId', make_secure_val(str(u.key().id())))
            self.redirect("/")
        else:
            self.write_form(user_name, user_password,
                            user_verify, user_email, error_username,
                            error_password, error_verify, error_email)

# login page handler


class LoginHandler(Handler):

    def write_form(self, error=""):
        self.render("login.html", user=self.user, error=error)

    def get(self):
        self.write_form()

    def post(self):
        user_name = self.request.get('username')
        user_password = self.request.get('password')

        db_user = db.GqlQuery(
            "select * from User where username = '%s'" % user_name).get()
        if db_user is not None:
            if valid_pw(user_name, user_password, db_user.password):
                self.set_cookie('userId', make_secure_val(
                    str(db_user.get_id())))
                self.redirect("/")
                return
        self.write_form("invalid login")

# logout page handler


class LogoutHandler(Handler):

    def get(self):
        # delete the userid cookie to logout
        self.set_cookie('userId', '')
        self.redirect("/signup")

# general methods section


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    return EMAIL_RE.match(email)


def is_existing_username(user_name):
    users = db.GqlQuery(
        "select * from User where username = '%s'" % user_name).get()
    if users is not None:
        return True


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    if h == make_pw_hash(name, pw, salt):
        return True
SECRET = 'bonjourjemappelleelodiecommentallezvous'


def make_secure_val(s):
    return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())


def check_secure_val(h):
    if h is not None:
        val = h.split('|')[0]
        if h == make_secure_val(val):
            return val
