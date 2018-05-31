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

#listen_ip = "172.23.50.154"
listen_ip = "0.0.0.0"
#listen_port = 10007
listen_port = 1234

import cherrypy
from urllib import urlopen
import hashlib
import sqlite3
import json
import mimetypes
import os
from bottle import route, run, template



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

        Page = open("LoginScreen/login.htm", "r")

        #Page = open("Loginscreen.html", "r")

        return Page


    @cherrypy.expose
    def chat(self):

        myusername = cherrypy.session.get('username')
        EncryptedSaltedPassword = cherrypy.session.get('encryptedsaltedpassword')
        Page = urlopen("http://cs302.pythonanywhere.com/getList?username=" + myusername.lower() + "&password=" + EncryptedSaltedPassword + "&json=1").read()
        Allusers = urlopen("http://cs302.pythonanywhere.com/listUsers").read()
        #Page += open("chat.html", "r")

        jsonloaded = json.loads(Page)
        Allusers = Allusers.split(',')

        #os.remove("onlineusers.db")
        conn = sqlite3.connect('onlineusers.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS stuffToPlot (username TEXT, ip REAL, location REAL, lastLogin REAL, port REAL, publicKey REAL, onlineStatus REAL)')
        c.execute('create unique index if not exists IndexUnique on stuffToPlot ( username )')

        for values in Allusers:
            #updates database with all users
            c.execute('''INSERT or ignore INTO stuffToPlot (username) VALUES (?)''', (values,))

        #sets online status to 0
        c.executemany('''UPDATE stuffToPlot SET onlineStatus= ?''', '0')

        for key,value in jsonloaded.items():
            #sets online status to 0 as default
            try: value['publicKey']
            except KeyError:
                value ['publicKey'] = 0

            #updates information from currently online users and sets online = 1
            c.execute('''UPDATE stuffToPlot SET ip = ?, location = ?, lastLogin = ?, port = ?, publicKey = ?, onlineStatus = ? where username = ?''', (value['ip'], value['location'], value['lastLogin'], value['port'], value['publicKey'], 1, value['username']))
            conn.commit()



        data = c.fetchall()
        response = template('onlineusers.db', rows=data)

        data2 = c.fetchall()
        response += template('onlineusers.db', rows=data2)

        return response



    @cherrypy.expose
    def testprint(self):
        print 'testprint'
        Page = open("Loginscreen.html", "r")
        return Page

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        #Takes username and password, encrypts it, checks it, if successful, redirects to chat page, if not refreshes current page
        EncryptedSaltedPassword = self.encrypt_string(password.lower()+username.lower())
        error = self.authoriseUserLogin(username,EncryptedSaltedPassword)

        if (error == 0):
            cherrypy.session['username'] = username;
            cherrypy.session['encryptedsaltedpassword'] = EncryptedSaltedPassword;
            raise cherrypy.HTTPRedirect('/chat')
        else:
            raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        EncryptedSaltedPassword = cherrypy.session.get('encryptedsaltedpassword')
        Page = urlopen("http://cs302.pythonanywhere.com/logoff?username=" + username.lower() + "&password=" + EncryptedSaltedPassword).read()
        cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/index')

        
    def authoriseUserLogin(self, username, EncryptedSaltedPassword):
        #This contacts the server and validates credentials, returns validation code
        print username
        print EncryptedSaltedPassword
        Page = urlopen("http://cs302.pythonanywhere.com/report?username=" + username.lower() + "&password=" + EncryptedSaltedPassword + "&location=1&ip=202.36.244.6&port=1001").read()
        if Page == "0, User and IP logged":
            return 0
        else:
            return 1

    def encrypt_string(self, hash_string):
        #this encrypts a string
        sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    @cherrypy.expose
    def Login_files(self, filename):
        f = open("LoginScreen/Login_files/" + filename, "r")
        data = f.read()
        f.close()
        #return correct mimetype
        cherrypy.response.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
        return data
          
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
