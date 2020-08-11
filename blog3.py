import webapp2
import logging
import cgi
import re
import jinja2
import os
import hmac
import random
import string
import datetime
import time

from google.appengine.ext import db

def hash_str(s):
  SECRET="imsosecret"
  sec = str(s)
  x = hmac.new(SECRET,sec).hexdigest()
  return str(x)

def make_secure_val(s):
  return str(s) + "|" + hash_str(s)

def check_secure_val(h):
  if (make_secure_val(h.split("|")[0]) == h):
    return h.split("|")[0]
  else:
    return None

def make_salt():
    salt = ""
    for x in range(1,26):
        salt = salt + random.choice(string.ascii_letters)
    return salt

def make_pw_hash(name,pw,salt=None):
    if(salt==None):
        salt = make_salt()
    returned = name+pw+salt
    return hash_str(returned) + "|" + salt #added salt messes everything up

def valid_pw(name,pw,h):
    h = str(h)
    if (make_pw_hash(name,pw,h.split("|")[1])==h):
        return True
    else:
        return False

VALID_RE = re.compile("\S")
def valid_text(username):
    return VALID_RE.match(username)

USER_RE = re.compile(r"^([a-z|A-Z|0-9|_|-]{3,20})$")  # 3-20 characters (a-zA-Z0-9_-)[\w|_|-]{3,20}+'\S{3,20}
def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r"\S{3,20}")          # 3-20 characters (any) (r"^\S+\@{1}+\S+\.{1}\S+")
def valid_password(username):
    return PASSWORD_RE.match(username)

EMAIL_RE = re.compile(r"^(\S*@\S*\.\S*$)$")  
def valid_email(username):
    return EMAIL_RE.match(username)


def escape_html(s):
   return cgi.escape(s, quote = True)

JINJA_ENVIRONMENT = jinja2.Environment( loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), extensions=['jinja2.ext.autoescape'])
template_signup = JINJA_ENVIRONMENT.get_template('templates/signup.html')
template_index = JINJA_ENVIRONMENT.get_template('templates/index.html')
template_login = JINJA_ENVIRONMENT.get_template('templates/login.html')
template_newpost = JINJA_ENVIRONMENT.get_template('templates/newpost.html')
template_posts = JINJA_ENVIRONMENT.get_template('templates/posts.html')
favoriteT = JINJA_ENVIRONMENT.get_template('templates/posts.html')

class Users(db.Model):

    username = db.StringProperty()
    pw = db.StringProperty()
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class Posts(db.Model):
   subject = db.StringProperty()
   content = db.TextProperty()
   created = db.DateTimeProperty(auto_now_add=True)
   coords  = db.GeoPtProperty()

class SignUp(webapp2.RequestHandler):

    def write_signup(self, username_error_msg="", password_error_msg="", verify_error_msg="", email_error_msg="", user_username="", user_email=""):

        template = {"replaceTitle": "Sign Up", "error_username":
        username_error_msg, "error_password": password_error_msg,
        "error_verify"  : verify_error_msg, "error_email"  :
        email_error_msg, "username_value": escape_html(user_username),
        "email_value"  : escape_html(user_email)}

        self.response.write(template_signup.render(template,check=check_secure_val(self.request.cookies.get('user_id'))))

    def get(self):
        logging.info("Hello MainPage GET")
        self.response.headers['Content-Type'] = 'text/html'
        self.write_signup()

    def post(self):
        global user_username

		## Your code here ><><><><><><><><><><><><><><><><>< 
		# You will need to set user_username_v
        user_username_v = valid_username(self.request.get("username"))
        user_username = self.request.get("username")
		# You will need to set user_userpassword_v
        user_password =  self.request.get("password")
        user_verify = self.request.get("verify")
        user_verify_v = user_verify == user_password
        user_password_v = valid_password(self.request.get("password"))
		# You will need to set user_email_v
        user_email = self.request.get("email")
        user_email_v = valid_email(self.request.get("email"))     

        username_error_msg = password_error_msg = verify_error_msg = email_error_msg = ""
        users = db.GqlQuery("SELECT * FROM Users "
                     "ORDER BY created DESC ")
        sameUsers=True
        for user in users:
          if(user_username==user.username):
            username_error_msg = "That user already exists."
            sameUsers = False
        if not(user_username_v):
            username_error_msg = "That's not a valid username."

        if (user_password != user_verify):
            password_error_msg = "Passwords do not match."
        elif not(user_password_v):
            password_error_msg = "That's not a valid password."
        if (user_email != "") and not(user_email_v):
            email_error_msg = "That's not a valid email."

        if not(user_username_v and user_password_v and user_verify_v and ((user_email == "") or user_email_v) and (user_password == user_verify) and sameUsers):
            self.write_signup(username_error_msg, password_error_msg, verify_error_msg, email_error_msg, user_username, user_email)
        else:
            usersObj = Users()
            usersObj.username = user_username
            usersObj.pw = str(make_pw_hash(user_username,user_password))
            usersObj.email = user_email
            usersObj.put()
            identification = str(usersObj.key().id())
            user_identification = make_secure_val(identification)# get the id of instance
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % user_identification)
  
	    #logging.info("*** ID of this Art is "+str(id))
	    #self.redirect('/blog/%s' % str(id))
            self.redirect("/index")

class LoginPage(webapp2.RequestHandler):
    def write_login(self, username_error_msg="", password_error_msg="", verify_error_msg="", email_error_msg="", user_username="", user_email=""):

        template = {"replaceTitle": "Login", "error_username": username_error_msg, "error_password": password_error_msg}
        self.response.write(template_login.render(template,check=check_secure_val(self.request.cookies.get('user_id'))))

    def get(self):
        logging.info("Hello MainPage GET")
        self.response.headers['Content-Type'] = 'text/html'
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        template = {"replaceTitle": "Login", "error_username": "", "error_password": ""}
        self.response.write(template_login.render(template))

    def post(self):
      	user_username = self.request.get("username")
      	user_password =  self.request.get("password")
      	users = db.GqlQuery("SELECT * FROM Users "
                     "ORDER BY created DESC ")
      	for user in users:
          if(user_username==user.username):
            if(valid_pw(user_username,user_password,user.pw)):
              identification = user.key().id()
              user_id = make_secure_val(identification)
              self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % user_id)
              self.redirect("/index")
        
        template = {"replaceTitle": "Login", "error_username": "Invalid login", "error_password": "Invalid login"}
        self.response.write(template_login.render(template))
        self.write_login()

class Index(webapp2.RequestHandler):
  
    def write_welcome(self, username=""):
        check = check_secure_val(self.request.cookies.get('user_id'))
        #user_username = ""
        
        if (check == "" or check==None):
          #self.redirect("/login")
          self.redirect("/login")

        else:
          usersname = self.checkThis(check)
          template = {"replaceTitle": "Welcome", "username": usersname}
          self.response.write(template_index.render(template,check=check_secure_val(self.request.cookies.get('user_id'))))
          
    def get(self):
        global user_username
	#JINJA_ENVIRONMENT = jinja2.Environment( loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), extensions=['jinja2.ext.autoescape'])
	#logging.info("Hello Welcome GET")
        logging.info("Hello Welcome GET")
       # self.write_welcome(user_username)
        self.write_welcome()

    def checkThis(self,check=""):
        users = db.GqlQuery("SELECT * FROM Users "
                     "ORDER BY created DESC ")
        for user in users:
          if(str(user.key().id())==check):
            #return "hello"
            return user.username
        return check
     
class LogoutPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/login")

class blog(webapp2.RequestHandler):

    def get(self):
	logging.info("*** ID of this Post in Posts class is "+str(id))
	posts = db.GqlQuery("SELECT * FROM Posts "
                     "ORDER BY created DESC ")
        check = check_secure_val(self.request.cookies.get('user_id'))
        #user_username = ""
        
        if (check == "" or check==None):
          #self.redirect("/login")
          self.redirect("/login")

        else:
          usersname = self.checkThis(check)
          
          self.response.write(template_posts.render(posts=posts,username=usersname,check=check))

    def checkThis(self,check=""):
        users = db.GqlQuery("SELECT * FROM Users "
                     "ORDER BY created DESC ")
        for user in users:
          if(str(user.key().id())==check):
            #return "hello"
            return user.username
        return check

    def write(self, *writeArgs):    
        self.response.write(" : ".join(writeArgs))

    def render_str(self, template, **params):
        tplt = JINJA_ENVIRONMENT.get_template('templates/'+template)
        return tplt.render(params)

    #def render(self, template, **kw):
     #   self.write(self.render_str(template, **kw))

class NewPost(webapp2.RequestHandler):

    def get(self, username_error_msg="", user_username="", user_email=""):
	user_username = user_email = ""
	logging.info("Hello MainPage GET")
        self.response.headers['Content-Type'] = 'text/html'
        #self.write_signup()
	template = {"ph_error": username_error_msg, "ph_content": escape_html(user_username), "ph_subject"   : escape_html(user_email)}
	check=check_secure_val(self.request.cookies.get('user_id'))
        usersname = self.checkThis(check)
	self.response.write(template_newpost.render(template,username=usersname,check=check))
    
    def checkThis(self,check=""):
        users = db.GqlQuery("SELECT * FROM Users "
                     "ORDER BY created DESC ")
        for user in users:
          if(str(user.key().id())==check):
            #return "hello"
            return user.username
        return check

    def post(self):
        global user_username
      #  db.GqlQuery("SELECT * FROM Users WHERE property = '%s'" % value)
		## Your code here ><><><><><><><><><><><><><><><><>< 
		# You will need to set user_username_v
	user_username_v = valid_text(self.request.get("subject"))
	user_username = self.request.get("subject")
		# You will need to set user_email_v
	user_email = self.request.get("content")
	user_email_v = valid_text(self.request.get("content")) 


        username_error_msg = ""

        if not(user_username_v and user_email_v):
            username_error_msg = "Need both a title and an entry!"
	    self.get(username_error_msg, user_username, user_email)

	else:
	    artObj = Posts()
	    artObj.subject = user_username
	    artObj.content = user_email
	    artObj.put()
	    id = artObj.key().id()   # get the id of instance
	    logging.info("*** ID of this Post is "+str(id))
	    self.redirect('/blog/%s' % str(id))
 	   # self.render_ascii(user_username, user_email,username_error_msg)

        #if (user_email_v):
         #   email_error_msg = 

        #if not(user_username_v or user_email_v):
    

    def write(self, *writeArgs):    
        self.response.write(" : ".join(writeArgs))

    def render_str(self, template, **params):
        tplt = JINJA_ENVIRONMENT.get_template('templates/'+template)
        return tplt.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_ascii(self, title="", art="",error=""):
	time.sleep(0.2)
	posts = db.GqlQuery("SELECT * FROM Posts "
                     "ORDER BY created DESC LIMIT 10")
	self.render("newpost.html", title=title, art=art, error=error, posts=posts,check=check_secure_val(self.request.cookies.get('user_id')))

class favorite(webapp2.RequestHandler):
    def write(self, *writeArgs):    
        self.response.write(" : ".join(writeArgs))

    def get(self, id):
	logging.info("*** ID of this Post in favorite is "+str(id))
	#template_values = {"favArt": db.get(4679521487814656)}
	self.render_ascii(id)

    def render_str(self, template, **params):
	tplt = JINJA_ENVIRONMENT.get_template('templates/posts.html')
        #tplt = JINJA_ENVIRONMENT.get_template('templates/'+favoriteT)
        return tplt.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(favoriteT, **kw))
    
    def render_ascii(self, id, title="", art="",error=""):
	intID = int(id)
	logging.info("*** ID of this Post in renderascii is "+str(id))
   	posts = {Posts.get_by_id(intID)}
	check=check_secure_val(self.request.cookies.get('user_id'))
        usersname = self.checkThis(check)
        
        #post = Posts.get_by_id(intID)
        #title = post.subject 
        #art = post.content
	self.render("posts.html", check=check,username=usersname,title=title, art=art,error=error, posts=posts)

    def checkThis(self,check=""):
        users = db.GqlQuery("SELECT * FROM Users "
                     "ORDER BY created DESC ")
        for user in users:
          if(str(user.key().id())==check):
            #return "hello"
            return user.username
        return check


application = webapp2.WSGIApplication([
    ('/blog', blog),
    ('/newpost', NewPost),
    ('/logout',LogoutPage),
    ('/index',Index),
    ('/login',LoginPage),
    ('/signup',SignUp),
    ('/blog/(\d+)', favorite)
    
  #  ('/map'),
    

], debug=True)
