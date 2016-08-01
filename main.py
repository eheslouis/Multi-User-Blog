import os
import jinja2
import webapp2
import hmac
import random
import string
import hashlib
import re
import time

from models import Article, User, Comment
from authen import Handler, SignupHandler, LoginHandler, LogoutHandler
from google.appengine.ext import db

# current dir /templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# jinja look for templates in template_dir
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# main page Handler


class BlogHandler(Handler):

    def write_form(self, error=""):
        articles = db.GqlQuery(
            "SELECT * FROM Article ORDER BY created DESC limit 10")
        self.render("front.html", user=self.user,
                    articles=articles, error=error)

    def get(self):
        self.write_form()

    def post(self, post_id=""):
        if self.user:
            submit = self.request.get('submit')
            like = self.request.get('like')
            dislike = self.request.get('dislike')
            post_id = self.request.get('postid')
            comment = self.request.get('comment')
            comment_id = self.request.get('commentid')
            commentdelete = self.request.get('commentdelete')
            commentupdate = self.request.get('commentupdate')

            if submit == 'delete':
                # delete article
                db.delete(Article.get_by_id(int(post_id)).key())
                time.sleep(0.1)
                self.redirect("/")
            elif submit == 'update':
                # update article
                self.redirect('/' + post_id + '/editPost')
            elif like:
                # like article
                article = Article.get_by_id(int(post_id))
                if not (str(self.user.get_id()) in article.like):
                    article.like.append(str(self.user.get_id()))
                    # remove dislike if user previously dislike article
                    if (str(self.user.get_id()) in article.dislike):
                        article.dislike.remove(str(self.user.get_id()))
                    article.put()
                    time.sleep(0.1)
                    self.write_form()
                else:
                    self.write_form("you already like that post")
            elif dislike:
                # dislike article
                article = Article.get_by_id(int(post_id))
                if not (str(self.user.get_id()) in article.dislike):
                    article.dislike.append(str(self.user.get_id()))
                    # remove like if user previously dislike article
                    if (str(self.user.get_id()) in article.like):
                        article.like.remove(str(self.user.get_id()))
                    article.put()
                    time.sleep(0.1)
                    self.write_form()
                else:
                    self.write_form("you already dislike that post")
            elif comment:
                # register comment
                commentdb = Comment(userid=self.user.get_id(
                ), articleid=int(post_id), content=comment)
                commentdb.put()
                time.sleep(0.1)
                self.redirect("/")
            elif commentupdate:
                # update comment
                self.redirect("/" + comment_id + "/editComment")
            elif commentdelete:
                # delete comment
                db.delete(Comment.get_by_id(int(comment_id)).key())
                time.sleep(0.1)
                self.redirect("/")
            else:
                self.redirect("/")
        else:
            self.redirect("/")

# Post page Handler


class PostPageHandler(BlogHandler):

    def get(self, post_id):
        article = Article.get_by_id(int(post_id))
        if article is None:
            self.error(404)
            return
        else:
            self.render("permalink.html", user=self.user, article=article)

# New Post and edit post page Handler


class NewPostHandler(Handler):

    def write_form(self, subject="", content="", error="", edit=False):
        self.render("newpost.html", user=self.user, subject=subject,
                    content=content, error=error, edit=edit)

    def get(self, post_id=""):
        if self.user:
            # edit post case
            if post_id is not "":
                article = Article.get_by_id(int(post_id))
                self.write_form(subject=article.subject,
                                content=article.content.replace('<br>', '\n'),
                                edit=True)
            else:
                # new post case
                self.write_form()
        else:
            self.redirect("/login")

    def post(self, post_id=""):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            submit = self.request.get('newpost')

            if submit == 'Submit':
                if subject and content:
                    # edit post case
                    if post_id is not "":
                        article = Article.get_by_id(int(post_id))
                        article.subject = subject
                        article.content = content.replace('\n', '<br>')
                    else:
                        # new post case
                        article = Article(subject=subject,
                                          content=content.replace(
                                              '\n', '<br>'),
                                          userid=self.user.get_id())
                    article.put()
                    self.redirect('/' + str(article.key().id()))
                else:
                    error = "we need both a subject and some content"
                    self.write_form(subject, content, error,
                                    edit=True if post_id is not "" else False)
            else:
                self.redirect('/')
        else:
            self.redirect('/')

# edit comment page handler


class EditCommentHandler(Handler):

    def get(self, comment_id):
        if self.user:
            if comment_id is not None:
                comment = Comment.get_by_id(int(comment_id))
                self.render("newcomment.html", user=self.user,
                            content=comment.content, comment_id=comment_id,
                            error="")

    def post(self, comment_id):
        if self.user:
            content = self.request.get('comment')
            if content:
                comment = Comment.get_by_id(int(comment_id))
                comment.content = content
                comment.put()
                time.sleep(0.1)
                self.redirect('/')
            else:
                error = "we need some content"
                self.render("newcomment.html", user=self.user,
                            content=content, comment_id=comment_id,
                            error=error)
        else:
            self.render('/')


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
