#WIKIAPP - FInal project for Udacity CS253
#Written by Stefan Preotesa

#Cookie check system in each handler?


import webapp2
import os
import jinja2

import hashlib
import string
import re
import sys
import logging
import time

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates') #defines the location of the 'templates' folder
jinja_environment = jinja2.Environment(autoescape = True, loader  = jinja2.FileSystemLoader(template_dir))

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

#------------------Entry Database model-------------------

class WikiEntry(db.Model):
    subject = db.StringProperty(required=False)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

#-------------------------------------------------------------MAIN Handlers------------------- 
class RenderBlog(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **params):
        j_template = jinja_environment.get_template(template)
        return j_template.render(**params)
    
    def render(self, template, **kw):
        return self.write(self.render_str(template, **kw))



class MainHandler(RenderBlog):
    def render_frontpage(self):
        self.render("frontpage.html") #add params for frontpage
        
    def get(self):
        entries = db.GqlQuery("SELECT * FROM WikiEntry ORDER BY created DESC limit 10")
        entries = list(entries)
        user_id = self.request.cookies.get("user_id", None)
        if user_auth(user_id):
            user_parameter = "Welcome %s" % user_id.split('|')[0]
        else:
            user_parameter = ""
        self.render("frontpage.html", entries = entries, user_parameter = user_parameter)
    

class EditPage(RenderBlog):
    def get(self, edit_post_subject):
        #from the page that was called for editing - the content is loaded into the form so that it can be edited
        user_id = self.request.cookies.get("user_id", None)
        logging.error("Edit Page user_id cookie is: %s" %user_id)
        if user_auth(user_id):
            post_subject = edit_post_subject.split("/_edit/")[0]
            entry = db.GqlQuery("SELECT * FROM WikiEntry WHERE subject = '%s'" %post_subject[1:])
            logging.error("%s" %post_subject)
            if entry is None:
                self.render("editpage.html", subject = post_subject, content = "Please fill in the content for the %s entry."%post_subject[1:])
            else:
                self.render("editpage.html", subject = post_subject[1:], content = "Please update content.")
        else:
            self.redirect("/login")


    def post(self, edit_post_subject):
        post_subject = edit_post_subject.split("/_edit/")[0]
        logging.error("Post subject is %s" %post_subject)
        subject = post_subject[1:]
        content = self.request.get("content")
        if subject and content: 
            #search for relevant subject
            #need to add for totally new entry
            entry = db.GqlQuery("SELECT * FROM WikiEntry WHERE subject = '%s' ORDER BY created DESC LIMIT 1" %subject)
            if entry is None:
                entry = WikiEntry(subject = subject, content = content)
                entry.put()
                self.redirect("%s" %post_subject)
            else:
                #replace content with new edited version
                '''key = entry.key()
                logging.error("%s" %key)
                edit_entry = key.get()
                edit_entry.content = content
                logging.error("%s" %edit_entry.content)
                edit_entry.put()
                self.redirect("%s" %post_subject)'''
                #temp
                entry = WikiEntry(subject = subject, content = content)
                entry.put()
                self.redirect("%s" %post_subject)


        #logging.error("Post subject is %s " %post_subject)
        #self.redirect("%s" %post_subject)


class WikiPage(RenderBlog):

    def get(self, post_subject):
        post_id = post_subject[1:]
        logging.error("%s" %post_id)
        entries = db.GqlQuery("SELECT * FROM WikiEntry WHERE subject = '%s' ORDER BY created DESC limit 1" %post_id)
        user_id = self.request.cookies.get("user_id", None)
        if list(entries) == []:
            self.redirect("/_edit/%s" %post_id)
        else:
            for entry in entries:    
                self.render("wikipage.html", 
                            subject = post_id, 
                            content = entry.content)




#---------------------------------------------------------LOGIN & REGISTRATION-----------------------------------------------------

#------------------Util functions-------------------------

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")

def valid_username(name):
    return USER_RE.match(name)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    if email == "":
        return True
    else:
        return EMAIL_RE.match(email)

def make_password_hash(name, password):
    if name and password:
        h = hashlib.sha256(name+password).hexdigest()
        return "%s|%s" %(name, h)

def check_password_hash(h):
    val = h.split('|')[0]
    if h == make_password_hash(val):
        return True
    else:
        return False    


#Litle experiment. Not sure if correct. After the signup or login, the user info is cached, with the username as key, and the db entry as value.
#Purpose - when the cookie checker is called on every page to identify the user, the db isn't hit.
#Investigat e further if possible security problems    
def cache_user(username):
    user_entry = db.GqlQuery("SELECT * FROM RegisteredUser WHERE username = '%s' LIMIT 1" %username)
    logging.error("DB HIT - Reason = User search!")
    if user_entry:
        for i in user_entry:
            user_hash = i.password 
            memcache.set(i.username, user_hash)
            logging.error("User entry cached!")

#authentication function. takes cookie as argument, returns wether cookie is a valid user by retrieving it from the cached user data or from the db user data.
#is this safe? could someone hack the cache easier than the db?
def user_auth(user_id):
    if user_id is None:
        logging.error("user_id is none")
        return False
    else:
        username = user_id.split('|')[0]
        logging.error("user_auth - Username is %s" %username)
        user_entry = db.GqlQuery("SELECT * FROM RegisteredUser WHERE username='%s' LIMIT 1" %username)
        user_hash = ""
        for i in list(user_entry):
            user_hash = i.password 
            logging.error("%s" %str(user_hash))
        
        #Problem here with getting users from the user cache.
        
        if user_hash is None:
            logging.error("cached_user_data is None")
            return False
            
        else:
            if str(user_hash) == str(user_id):
                logging.error("user found in cached user data")
                return True
            else:
                logging.error("user not found")
                return False
    

#------------------User Database--------------------------

class RegisteredUser(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    register_time = db.DateTimeProperty(auto_now_add = True)
    
#------------------Handlers-------------------------------
class LoginHandler(RenderBlog):
    def get(self):
        self.render("login.html", 
                    username = "", 
                    username_error = "",
                    password = "", 
                    password_error = "")

    def post(self):
        username_error = ""
        password_error = ""

        input_user = self.request.get("username")
        logging.error("%s" %input_user)
        input_password = self.request.get("password")

        user_db_check = db.GqlQuery("SELECT * FROM RegisteredUser WHERE username = '%s'" %input_user)

        if user_db_check is None:
            username_error == "Not a valid User Name!"
            self.render("login.html", username = input_user, username_error = username_error, password = "", password_error = "")
        else:
            user_pw_hash = make_password_hash(input_user, input_password)
            logging.error("%s" %user_pw_hash)
            for i in list(user_db_check):
                if user_pw_hash == i.password:
                    logging.error("USER CHECK!")
                    self.request.headers['Content-Type'] = 'text/plain'
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/' %str(user_pw_hash))
                    #cache_user(input_user)
                    self.redirect("/")
                else:
                    self.response.out.write("FAAAAIIILLLLLL")





class SignUpHandler(RenderBlog):
    def get(self):
        self.render("registration.html",
                    username = "",
                    password = "",
                    verify = "",
                    username_error = "",
                    password_error = "",
                    verify_error = "",
                    email_error = "")

    def post(self):
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        
        username = self.request.get("username")
        password = self.request.get("password")
        email = self.request.get("email")
        verify = self.request.get("verify")
        input_email = self.request.get("email")

        validity = True
            
        if not valid_username(username):
            username_error = "Please enter a valid user name!"
            validity = False
        
        user_db_check = db.GqlQuery("SELECT * FROM RegisteredUser")
        for entry in user_db_check:
            if entry.username == username:
                validity = False
                username_error = "User name already exists!"
            
        if not valid_password(password):
            password_error = "Please enter a valid password!"
            validity = False   
        
        if verify != password:
            verify_error = "Password verification failed."
            validity = False
            
        if email and not valid_email(email):
            email_error = "Please enter a valid email address!"
            validity = False
        
        if not validity:
            self.render("registration.html", username = username,
                                            username_error = username_error,
                                            password_error = password_error,
                                            verify_error = verify_error,
                                            email = email,
                                            email_error = email_error)    
        else:
            #make hash
            user_password_hash = str(make_password_hash(username, password))
            
            #set cookie
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header("Set-Cookie","user_id=%s;Path=/" % user_password_hash)
            
            #add to db
            user = RegisteredUser(username = username, password = user_password_hash, email = email)
            user.put()
            #time.sleep(0.2) #test version db write not happening ast enough and cache fails to retrieve user data. therefore pause.
            cache_user(username)
            self.response.out.write("welcome "+ username + "!")
            
            self.redirect('/')
    

class LogoutHandler(RenderBlog):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        user_id = self.request.cookies.get("user_id", None)
        if user_id:
            self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/' %"")
            self.redirect("/")
        else:
            self.response.out.write("No user is logged in!")
    
class FlushHandler(webapp2.RequestHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')

#---------------------------------------------------------CALLER-------------------------------------------------------------------
app = webapp2.WSGIApplication([
                                ('/', MainHandler),
                                ('/login', LoginHandler),
                                ('/signup', SignUpHandler),
                                ('/logout', LogoutHandler),
                                ('/_edit' + PAGE_RE, EditPage),
                                ('/blog/flush', FlushHandler),
                                (PAGE_RE, WikiPage)
                                ], debug=True)
