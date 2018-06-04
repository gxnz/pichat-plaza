#!/usr/bin/python
""" server.py

    COMPSYS302 - Software Design
    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

import cherrypy
from urllib import urlopen
import hashlib
import sqlite3
import json
import mimetypes
import os
import threading
from apscheduler.schedulers.background import BackgroundScheduler
import sched, time
import pandas as pd
import socket
from threading import Timer,Thread,Event
from time import gmtime, strftime
import urllib2
import atexit
import sys
import os.path

# The address we listen for connections on
listen_port = 10007
myPort = '10007'

myLocation = "2"

ip = socket.gethostbyname(socket.gethostname())
print "IP Detected as " + ip
listen_ip = ip
myIP = ip
myIP = "222.155.40.199"

class perpetualTimer():

   def __init__(self,t,hFunction):
      self.t=t
      self.hFunction = hFunction
      self.thread = Timer(self.t,self.handle_function)

   def handle_function(self):
      self.hFunction()
      self.thread = Timer(self.t,self.handle_function)
      self.thread.start()

   def start(self):
      self.thread.start()

   def cancel(self):
      self.thread.cancel()


class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                  'tools.sessions.storage_type': "File",
                        'tools.sessions.storage_path': 'session',
                        'tools.sessions.timeout': 60,

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


        return Page


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def sendMessage(self, recipient, message):

        #code to send
        conn2 = sqlite3.connect("onlineusers.db")
        c2 = conn2.cursor()
        c2.execute("SELECT ip FROM stuffToPlot WHERE username = '%s'" % str(recipient))
        ipretrieve = c2.fetchall()
        ip = str(ipretrieve[0][0].encode('utf-8'))

        c2.execute("SELECT port FROM stuffToPlot WHERE username = '%s'" % str(recipient))
        portretrieve = c2.fetchall()
        port = str(int(portretrieve[0][0]))
        print ip
        print port

        me = cherrypy.session.get('username')
        epoch = int(time.time())
        dict = {"sender": str(me), "destination": str(recipient), "message": str(message), "stamp": epoch}
        data = json.dumps(dict)

        url = 'http://' + str(ip) + ':' + str(port) + '/receiveMessage'
        try:
            returned = urllib2.Request(url, data, {'Content-Type':'application/json'})
            returned2 = urllib2.urlopen(returned)
            errormessage = "(Sent Successfully)"
        except:
            errormessage = "(Failed to Send)"


        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS messages (username TEXT)')

        try:
            c.execute('ALTER TABLE messages ADD COLUMN ' + recipient + ';')
        except:
            pass

        print "I sent this to " + recipient + ": " + message
        currenttime = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        username = cherrypy.session.get('username')
        message = currenttime + " - " + username + ": " + message + " " + errormessage
        c.execute('''INSERT INTO messages ( ''' + recipient + ''') VALUES (?)''', (message,))
        conn.commit()

        # extracts data from database to output
        c.execute("select " + recipient + " from messages")
        Table = """<div style="background: rgba(255, 255, 255, 1.0);"><bold><font color="black">"""
        Table += """<table>"""

        Table += "<tr><th>Chat</th></tr>"
        for row in c.fetchall():
            if (str(row[0]) != "None"):
                Table += "<tr><td>" + str(row[0]) + "</td></tr>"

        Table += "</table>"
        Table += "</font></bold></div>"
        Table = Table.encode('utf-8')

        Html_file = open("ChatScreen/usermessages/" + recipient + ".html", "w+")
        Html_file.write(Table)
        Html_file.close()

        conn.close()
        raise cherrypy.HTTPRedirect('/chat')

    @cherrypy.expose
    def sendFile(self, recipient, file):
        return "Send File"
        #raise cherrypy.HTTPRedirect('/chat')

    def receiveFile(self):
        sender = cherrypy.request.json['sender']
        destination = cherrypy.request.json['destination']
        file = cherrypy.request.json['file']
        filename = cherrypy.request.json['filename']
        content_type = cherrypy.request.json['content_type']
        stamp = cherrypy.request.json['stamp']

    @cherrypy.expose
    def getProfile(self, profile_username, sender):
        print profile_username + " is requesting the profile of " + sender
        pass

    @cherrypy.expose
    def requestProfile(self, username):
        conn2 = sqlite3.connect("onlineusers.db")
        c2 = conn2.cursor()
        c2.execute("SELECT ip FROM stuffToPlot WHERE username = '%s'" % str(username))
        ipretrieve = c2.fetchall()
        ip = str(ipretrieve[0][0].encode('utf-8'))

        c2.execute("SELECT port FROM stuffToPlot WHERE username = '%s'" % str(username))
        portretrieve = c2.fetchall()
        port = str(int(portretrieve[0][0]))
        print ip
        print port

        me = cherrypy.session.get('username')
        dict = {"profile_username": str(username), "sender": str(me)}
        data = json.dumps(dict)

        url = 'http://' + str(ip) + ':' + str(port) + '/getProfile'

        try:
            returned = urllib2.Request(url, data, {'Content-Type':'application/json'})
            returned2 = urllib2.urlopen(returned).read()

            # file = open('ChatScreen/userprofiles/' + username + 'profile.html', 'w+')
            # file.write(str(returned2))
            # file.close

            jsonloaded = json.loads(returned2)

            conn = sqlite3.connect('/ChatScreen/userprofiles/' + username + '.db')
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS profiledata (lastUpdated REAL, fullname TEXT, position REAL, description TEXT, location TEXT, picture TEXT, encoding REAL, encryption REAL, decryptionKey)')

            for key, value in jsonloaded.items():
                c.execute('''UPDATE profiledata SET lastUpdated = ?, fullname = ?, position = ?, description = ?, location = ?, picture = ?, encoding = ?, encryption = ?, decryptionKey = ?''', (value['lastUpdated'], value['fullname'], value['position'], value['description'], value['location'], value['picture'], value['encoding'], value['encryption'], value['decryptionKey']))
                conn.commit()

            print "Retrieved profile from " + username
        except:

            print "Failed to retrieve profile from " + username
            pass






    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self):
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS messages (username TEXT)')

        senderclient = cherrypy.request.json['sender']
        messagedata = cherrypy.request.json['message']

        try:
            c.execute('ALTER TABLE messages ADD COLUMN ' + senderclient + ';')
        except:
            pass

        print senderclient + " sent this: " + messagedata

        currenttime = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        messagedata = currenttime + " - " + senderclient + ": " + messagedata
        c.execute('''INSERT INTO messages ( ''' + senderclient + ''') VALUES (?)''', (messagedata,))
        conn.commit()

        # extracts data from database to output
        c.execute("select " + senderclient + " from messages")
        Table = """<div style="background: rgba(255, 255, 255, 1.0);"><bold><font color="black">"""
        Table += """<table>"""

        Table += "<tr><th>Chat</th></tr>"
        for row in c.fetchall():
            if (str(row[0]) != "None"):
                Table += "<tr><td>" + str(row[0]) + "</td></tr>"

        Table += "</table>"
        Table += "</font></bold></div>"
        Table = Table.encode('utf-8')

        # t = ResumableTimer(5, 'signin')
        # t.start()

        Html_file = open("ChatScreen/usermessages/" + senderclient + ".html", "w+")
        Html_file.write(Table)
        Html_file.close()

        conn.close()

        cherrypy.session['notification'] = senderclient;
        raise cherrypy.HTTPRedirect('/chat')

        return "0"


    @cherrypy.expose
    def ping(self,sender):
        print "ping"
        print sender
        return "0"


    @cherrypy.expose
    def chat(self):

        print cherrypy.session.get('username')
        myusername = cherrypy.session.get('username')
        EncryptedSaltedPassword = cherrypy.session.get('encryptedsaltedpassword')

        OnlineUsersList = urlopen("http://cs302.pythonanywhere.com/getList?username=" + myusername.lower() + "&password=" + EncryptedSaltedPassword + "&json=1").read()
        Allusers = urlopen("http://cs302.pythonanywhere.com/listUsers").read()
        #Page += open("chat.html", "r")

        jsonloaded = json.loads(OnlineUsersList)
        Allusers = Allusers.split(',')

        #os.remove("onlineusers.db")
        conn = sqlite3.connect('onlineusers.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS stuffToPlot (username TEXT, ip REAL, location REAL, lastLogin REAL, port REAL, publicKey REAL, onlineStatus REAL, realname REAL)')
        c.execute('create unique index if not exists IndexUnique on stuffToPlot ( username )')

        for values in Allusers:
            #updates database with all users
            c.execute('''INSERT or ignore INTO stuffToPlot (username) VALUES (?)''', (values,))

        #sets online status to 0
        c.executemany('''UPDATE stuffToPlot SET onlineStatus= ?''', '0')

        for key,value in jsonloaded.items():

            #sets publickey to None if doesnt exist
            try: value['publicKey']
            except KeyError:
                value ['publicKey'] = None

            #updates information from currently online users and sets online = 1
            c.execute('''UPDATE stuffToPlot SET ip = ?, location = ?, lastLogin = ?, port = ?, publicKey = ?, onlineStatus = ? where username = ?''', (value['ip'], value['location'], value['lastLogin'], value['port'], value['publicKey'], 1, value['username']))
            conn.commit()

            #self.requestProfile(value['username'])

        #initialising image
        data_uri_greendot = open('resource/greendot.png', 'rb').read().encode('base64').replace('\n', '')
        greendot = '<img src="data:image/png;base64,{0}">'.format(data_uri_greendot)
        data_uri_nodot = open('resource/nodot.png', 'rb').read().encode('base64').replace('\n', '')
        nodot = '<img src="data:image/png;base64,{0}">'.format(data_uri_nodot)
        data_uri_history = open('resource/history.png', 'rb').read().encode('base64').replace('\n', '')
        history = '<img src="data:image/png;base64,{0}">'.format(data_uri_history)
        data_uri_notification = open('resource/notification.png', 'rb').read().encode('base64').replace('\n', '')
        notification = '<img src="data:image/png;base64,{0}">'.format(data_uri_notification)

        #extracts data from database to output
        c.execute("select username, realname, onlineStatus from stuffToPlot")
        Table = """<html><head></head>"""
        Table += """<div style="background: rgba(0, 0, 0, 0.15);"><bold><font color="white">"""

        Table += """<body><table><col width="1"><col width="1">"""
        Table += "<tr><th>Online</th><th>Status</th><th>Client</th></tr>"
        for row in c.fetchall():
            if row[2] == 1.0:
                Table += "<th>" + greendot + "</td>"
            else:
                Table += "<th>" + nodot + "</td>"
            if (cherrypy.session.get('notification') == str(row[0])):
                Table += "<th>" + notification + "</td>"
                cherrypy.session['notification'] = None;
            elif (os.path.isfile("./ChatScreen/usermessages/" + str(row[0]) + ".html") == True):
                Table += "<th>" + history + "</td>"
            else:
                Table += "<th>" + nodot + "</td>"
            if row[1] == None:
                Table += """<td><a HREF="javascript:includeHTMLmessages('""" + row[0] + """.html')">""" + row[0] + "</td></tr>"
            else:
                Table += """<td><a HREF="javascript:includeHTMLmessages('""" + row[0] + """.html')">""" + row[1] + "</td></tr>"
        Table += "</table></body>"

        Table += "</font></bold></div></html>"
        Table = Table.encode('utf-8')

        # t = ResumableTimer(5, 'signin')
        # t.start()

        Html_file = open("ChatScreen/Chat_files/onlinetable.html", "w+")
        Html_file.write(Table)
        Html_file.close()

        Tablehtml = open("ChatScreen/Chat_files/onlinetable.html", "r")
        Templatehtml = open("ChatScreen/Chat.htm", "r")

        conn.close()
        return Templatehtml


    @cherrypy.expose
    def testprint(self):
        print 'testprint'


    @cherrypy.expose
    def signin(self, username=None, password=None):

        if username == None:
            username = cherrypy.session.get('username')
        if password == None:
            EncryptedSaltedPassword = cherrypy.session.get('encryptedsaltedpassword')
        else:
            EncryptedSaltedPassword = self.encrypt_string(password.lower() + username.lower())


        print 'Signing In'
        #Takes username and password, encrypts it, checks it, if successful, redirects to chat page, if not refreshes current page


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
        try:
            os.remove("ChatScreen/Chat_files/onlinetable.html")
        except OSError:
            pass
        print 'Signing Out'
        raise cherrypy.HTTPRedirect('/index')

        
    def authoriseUserLogin(self, username, EncryptedSaltedPassword):
        #This contacts the server and validates credentials, returns validation code
        print username
        print EncryptedSaltedPassword
        Page = urlopen("http://cs302.pythonanywhere.com/report?username=" + username.lower() + "&password=" + EncryptedSaltedPassword + "&location=" + myLocation + "&ip=" + myIP + "&port=" + myPort).read()
        if Page == "0, User and IP logged":
            print "Login Successful"
            return 0

        else:
            print "Login Unsuccessful"
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

    @cherrypy.expose
    def Chat_files(self, filename):
        f = open("ChatScreen/Chat_files/" + filename, "r")
        data = f.read()
        f.close()
        # return correct mimetype
        cherrypy.response.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
        return data

    @cherrypy.expose
    def usermessages(self, filename):
        f = open("ChatScreen/usermessages/" + filename, "r")
        data = f.read()
        f.close()
        # return correct mimetype
        cherrypy.response.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
        return data

    atexit.register(signout)

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
