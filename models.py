import os
import jinja2
from google.appengine.ext import db

# current dir /templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# jinja look for templates in template_dir
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Article Entity


class Article(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    userid = db.IntegerProperty(required=True)
    # list of userid who like the article
    like = db.StringListProperty()
    # list of userid who dislike the article
    dislike = db.StringListProperty()

    def getUsername(self):
        return User.get_by_id(int(self.userid)).username

    def get_id(self):
        return self.key().id()

    # render the article
    def renderpost(self, user):
        is_like = False
        is_dislike = False
        # check if the current user likes or dislikes the article
        if user:
            if str(user.get_id()) in self.like:
                is_like = True
            if str(user.get_id()) in self.dislike:
                is_dislike = True
        return render_str("post.html", user=user, article=self, like=is_like,
                          dislike=is_dislike)

    # render the comments related to this article
    def rendercomment(self, user):
        comments = db.GqlQuery(
            "SELECT * FROM Comment WHERE articleid = %s ORDER BY created"
            % self.get_id())
        comment_render = ""
        if comments is not None:
            for comment in comments:
                if comment is not None:
                    comment_render += render_str("comment.html",
                                                 user=user, comment=comment)
        return comment_render

# User Entity


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()

    def get_id(self):
        return self.key().id()

# Comment Entity


class Comment(db.Model):
    userid = db.IntegerProperty(required=True)
    articleid = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def getUsername(self):
        return User.get_by_id(int(self.userid)).username

    def get_id(self):
        return self.key().id()


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
