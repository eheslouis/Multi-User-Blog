import os
import jinja2
import webapp2
import hmac
import random
import string
import hashlib
import re
import time

from google.appengine.ext import db

#current dir /templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates') 
#jinja look for templates in template_dir
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
												autoescape = True)

#Article Entity
class Article(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	userid = db.IntegerProperty(required = True)
	#list of userid who like the article
	like = db.StringListProperty()
	#list of userid who dislike the article
	dislike = db.StringListProperty()

	def getUsername(self):
		return User.get_by_id(int(self.userid)).username

	def get_id(self):
		return self.key().id()

	#render the article
	def renderpost(self, user):
		is_like = False
		is_dislike = False
		#check if the current user likes or dislikes the article
		if user:
			if str(user.get_id()) in self.like:
				is_like = True
			if str(user.get_id()) in self.dislike:
				is_dislike = True
		return render_str("post.html", user = user, article = self, like = is_like, dislike = is_dislike)

	#render the comments related to this article
	def rendercomment(self, user):
		comments = db.GqlQuery("SELECT * FROM Comment WHERE articleid = %s ORDER BY created" % self.get_id())
		comment_render = ""
		if comments is not None:
			for comment in comments:
				if comment is not None:
					comment_render += render_str("comment.html", user = user, comment = comment)
		return comment_render

#User Entity
class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

	def get_id(self):
		return self.key().id()

#Comment Entity
class Comment(db.Model):
	userid = db.IntegerProperty(required = True)
	articleid = db.IntegerProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	def getUsername(self):
		return User.get_by_id(int(self.userid)).username

	def get_id(self):
		return self.key().id()

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

	def set_cookie(self,name, value):
		self.response.headers['Content-Type'] = 'text/plain'
		self.response.headers.add_header('Set-Cookie', str('%s=%s; Path=/' % (name, value)))

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('userId')
		self.user = uid and User.get_by_id(int(uid))

#main page Handler
class BlogHandler(Handler):
	def write_form(self, error = ""):
		articles = db.GqlQuery("SELECT * FROM Article ORDER BY created DESC limit 10")
		self.render("front.html", user = self.user, articles = articles, error = error)

	def get(self):
		self.write_form()

	def post(self, post_id = ""):
		submit = self.request.get('submit')
		like = self.request.get('like')
		dislike = self.request.get('dislike')
		post_id = self.request.get('postid')
		comment = self.request.get('comment')
		comment_id = self.request.get('commentid')
		commentdelete = self.request.get('commentdelete')
		commentupdate = self.request.get('commentupdate')

		if submit == 'delete':
			#delete article
			db.delete(Article.get_by_id(int(post_id)).key())
			time.sleep(0.1)
			self.redirect("/")
		elif submit == 'update':
			#update article
			self.redirect('/'+ post_id+'/editPost')
		elif like:
			#like article
			article = Article.get_by_id(int(post_id))
			if not (str(self.user.get_id()) in article.like):
				article.like.append(str(self.user.get_id()))
				#remove dislike if user previously dislike article
				if (str(self.user.get_id()) in article.dislike):
					article.dislike.remove(str(self.user.get_id()))
				article.put()
				time.sleep(0.1)
				self.write_form()
			else:
				self.write_form("you already like that post")
		elif dislike:
			#dislike article
			article = Article.get_by_id(int(post_id))
			if not (str(self.user.get_id()) in article.dislike):
				article.dislike.append(str(self.user.get_id()))
				#remove like if user previously dislike article
				if (str(self.user.get_id()) in article.like):
					article.like.remove(str(self.user.get_id()))
				article.put()
				time.sleep(0.1)
				self.write_form()
			else:
				self.write_form("you already dislike that post")
		elif comment:
			#register comment
			commentdb = Comment(userid = self.user.get_id(), articleid = int(post_id), content = comment)
			commentdb.put()
			time.sleep(0.1)
			self.redirect("/")
		elif submit == 'commentupdate':
			#update comment
			self.redirect("/"+comment_id+"/editComment")
		elif submit == 'commentdelete':
			#delete comment
			db.delete(Comment.get_by_id(int(comment_id)).key())
			time.sleep(0.1)
			self.redirect("/")
		else:
			self.redirect("/")

#Post page Handler
class PostPageHandler(BlogHandler):
	def get(self, post_id):
		article = Article.get_by_id(int(post_id))
		if article is None:
			self.error(404)
			return
		else:
			self.render("permalink.html", user = self.user, article = article)

#New Post and edit post page Handler
class NewPostHandler(Handler):
	def write_form(self, subject = "", content = "", error = ""):
		self.render("newpost.html", user = self.user, subject = subject, content = content, error = error)

	def get(self, post_id = ""):
		if self.user:
			#edit post case
			if post_id is not "":
				article = Article.get_by_id(int(post_id))
				self.write_form(subject = article.subject, content = article.content.replace('<br>', '\n'))
			else:
				#new post case
				self.write_form()
		else:
		    self.redirect("/login")

	def post(self, post_id=""):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			#edit post case
			if post_id is not "":
				article = Article.get_by_id(int(post_id))
				article.subject = subject
				article.content = content.replace('\n', '<br>')
			else:
				#new post case
				article = Article(subject = subject, content = content.replace('\n', '<br>'), userid = self.user.get_id())
			article.put()
			self.redirect('/'+ str(article.key().id()))
		else:
			error = "we need both a subject and some content"
			self.write_form(subject, content, error)

#edit comment page handler
class EditCommentHandler(Handler):
	def get(self, comment_id):
		if self.user:
			if comment_id is not None:
				comment = Comment.get_by_id(int(comment_id))
				self.render("newcomment.html", user = self.user, content = comment.content, comment_id = comment_id, error = "")

	def post(self, comment_id):
		content = self.request.get('comment')
		if content:
			comment = Comment.get_by_id(int(comment_id))
			comment.content = content
			comment.put()
			time.sleep(0.1)
			self.redirect('/')
		else:
			error = "we need some content"
			self.render("newcomment.html", user = self.user, content = content, comment_id = comment_id, error = error)

#signup page handler
class SignupHandler(Handler):
	def write_form(self, name = "", password = "", verify = "", email = "", 
		error_username = "", error_password = "", error_verify = "", 
		error_email = ""):
		self.render("signup.html", user = self.user, username = name, password = password, 
			verify = verify, email = email, error_username = error_username, 
			error_password = error_password, error_verify = error_verify, 
			error_email = error_email)

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
		
		#verufy all parameters
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

		if not(error_username or error_email or error_verify or error_password):
			#if no error, create new user account
			u = User(username = user_name, password = make_pw_hash(user_name, user_password), email = user_email)
			u.put()
			self.set_cookie('userId', make_secure_val(str(u.key().id())))
			self.redirect("/")
		else:
			self.write_form(user_name, user_password, 
				user_verify, user_email, error_username, 
				error_password, error_verify, error_email)

#login page handler
class LoginHandler(Handler):
	def write_form(self, error = ""):
		self.render("login.html", user = self.user, error = error)

	def get(self):
		self.write_form()

	def post(self):
		user_name = self.request.get('username')
		user_password = self.request.get('password')

		db_user = db.GqlQuery("select * from User where username = '%s'" % user_name).get()
		if db_user is not None:
			if valid_pw(user_name, user_password, db_user.password):
				self.set_cookie('userId', make_secure_val(str(db_user.get_id())))
				self.redirect("/")
				return
		self.write_form("invalid login")

#logout page handler
class LogoutHandler(Handler):
	def get(self):
		#delete the userid cookie to logout
		self.set_cookie('userId', '')
		self.redirect("/signup")		

#general methods section
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

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
	users = db.GqlQuery("select * from User where username = '%s'" % user_name).get()
	if users is not None: 
		return True

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
	salt=h.split(',')[1]
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

app = webapp2.WSGIApplication([
	('/', BlogHandler),
	('/newpost', NewPostHandler),
	('/([0-9]+)/editPost', NewPostHandler),
	('/([0-9]+)', PostPageHandler),
	('/([0-9]+)/editComment', EditCommentHandler),
	('/signup', SignupHandler),
	('/login', LoginHandler),
	('/logout', LogoutHandler)
], debug=True)
