#!/usr/bin/python
""" server.py

    COMPSYS302 - Software Design
    Author: Andrew Chen (andrew.chen@auckland.ac.nz)
    Last Edited: 19/02/2018

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 1234

import cherrypy
from urllib import urlopen
import hashlib
import sqlite3

class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }                 

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        #Page = "Welcome! This is a test website for COMPSYS302!<br/>"
        Page = open("startscreen.html", "r")

        #try:
            #Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            #Page += "Here is some bonus text because you've logged in!"
        #except KeyError: #There is no username
            
            #Page += "Click here to <a href='login'>login</a>."
        return Page
        
    @cherrypy.expose
    def login(self):
        Page = open("loginscreen.html", "r")
        return Page

    @cherrypy.expose
    def chat(self):
        #print user
        #print EncryptedSaltedPassword
        username = cherrypy.session.get('username')
        EncryptedSaltedPassword = cherrypy.session.get('encryptedsaltedpassword')
        Page = urlopen("http://cs302.pythonanywhere.com/getList?username=" + username.lower() + "&password=" + EncryptedSaltedPassword).read()
        #Page += open("chat.html", "r")
        conn = sqlite3.connect('onlineusers.db')
        c = conn.cursor()
        self.create_table(c, conn)
        for row in c.execute('SELECT * FROM onlineusers'):
            print(row)
        return Page

    def create_table(self, c, conn):
        c.execute('CREATE TABLE IF NOT EXISTS stuffToPlot(user TEXT, status REAL)')
        c.execute("INSERT INTO stuffToPlot VALUES('someone', 1)")
        conn.commit()
        #c.close()
        #conn.close

    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        #global user
        #user = username
        #global EncryptedSaltedPassword
        EncryptedSaltedPassword = self.encrypt_string(password.lower()+username.lower())
        error = self.authoriseUserLogin(username,EncryptedSaltedPassword)
        if (error == 0):
            cherrypy.session['username'] = username;
            cherrypy.session['encryptedsaltedpassword'] = EncryptedSaltedPassword;
            #cherrypy.session['username'] = username;
            #raise cherrypy.HTTPRedirect('/chat')
            raise cherrypy.HTTPRedirect('/chat')
        else:
            raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if (username == None):
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
        
    def authoriseUserLogin(self, username, EncryptedSaltedPassword):
        print username
        print EncryptedSaltedPassword
        #if (username.lower() == "gxu630") and (password.lower() == "mainrabbit"):
        Page = urlopen("http://cs302.pythonanywhere.com/report?username=" + username.lower() + "&password=" + EncryptedSaltedPassword + "&location=1&ip=202.36.244.6&port=1001").read()
        if Page == "0, User and IP logged":
            return 0
        else:
            return 1

    def encrypt_string(self, hash_string):
        sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature
          
def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/")

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True,
                           })

    print "========================="
    print "University of Auckland"
    print "COMPSYS302 - Software Design Application"
    print "========================================"                       
    
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()
