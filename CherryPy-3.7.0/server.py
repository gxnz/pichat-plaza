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
import time
import socket
import base64
from time import gmtime, strftime
import urllib2
import os.path
import string
import random

# The address we listen for connections on
listen_port = 10007
myPort = '10007'

myLocation = "2"

ip = socket.gethostbyname(socket.gethostname())
print "IP Detected as " + ip
listen_ip = ip
myIP = ip
#myIP = "222.155.40.199"



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

        Page = open("LoginScreen/Login.htm", "r")


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
        conn2.close()
        raise cherrypy.HTTPRedirect('/chat')

    @cherrypy.expose
    def sendFile(self, recipient, thefile):
        with open(thefile, "rb") as f:
            encoded = base64.b64encode(f.read())

        conn2 = sqlite3.connect("onlineusers.db")
        c2 = conn2.cursor()
        c2.execute("SELECT ip FROM stuffToPlot WHERE username = '%s'" % str(recipient))
        ipretrieve = c2.fetchall()
        ip = str(ipretrieve[0][0].encode('utf-8'))

        c2.execute("SELECT port FROM stuffToPlot WHERE username = '%s'" % str(recipient))
        portretrieve = c2.fetchall()
        port = str(int(portretrieve[0][0]))

        mimetype = str(mimetypes.guess_type(thefile)[0])
        me = cherrypy.session.get('username')
        tuple = {
        "sender" : me,
        "destination" : recipient,
        "file" : encoded,
        "filename" : thefile,
        "content_type" : mimetype,
        "stamp" : time.time()
        }
        jsonned = json.dumps(tuple)

        try:
            returned = urllib2.Request("http://" + ip + ":" + port + "/receiveFile", jsonned, {'Content-Type':'application/json'})
            returned2 = urllib2.urlopen(returned).read()
            print returned2

            print "Successfully sent a file to " + recipient

            self.receiveMessage(2, recipient, thefile)

        except:
            self.receiveMessage(3, recipient, thefile)

        conn2.close()
        raise cherrypy.HTTPRedirect('/chat')


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self):
        print "Receiving File . . ."
        sender = cherrypy.request.json['sender']
        destination = cherrypy.request.json['destination']
        file = cherrypy.request.json['file']
        filename = cherrypy.request.json['filename']
        content_type = cherrypy.request.json['content_type']
        stamp = cherrypy.request.json['stamp']

        decoded = base64.b64decode(file)

        file = open("downloads/" + filename, 'w+')
        file.write(decoded)
        file.close()

        print "File: " + filename + " successfully received from " + sender

        self.receiveMessage(1, sender, filename)

        return "0"

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getProfile(self):

        jsondata = cherrypy.request.json
        profile_username = jsondata['profile_username']
        sender = jsondata['sender']

        print profile_username + " is requesting the profile of " + sender

        conn5 = sqlite3.connect('ChatScreen/userprofiles/profiledatabase.db')
        c5=conn5.cursor()
        c5.execute("SELECT lastUpdated, fullname, position, description, location, picture FROM profiledata WHERE profile_username = ?", (profile_username,))
        output = c5.fetchall()
        lastUpdated = output[0][0]
        fullname = output[0][1]
        position = output[0][2]
        description = output[0][3]
        location = output[0][4]
        picture = output[0][5]

        tosend = {'lastUpdated': lastUpdated, 'fullname': fullname, 'position': position, 'description': description, 'location': location, 'picture': picture}
        jsonned = json.dumps(tosend)

        conn5.close()
        return jsonned

    @cherrypy.expose
    def requestProfile(self, username):

        conn3 = sqlite3.connect('onlineusers.db')
        c3 = conn3.cursor()
        c3.execute("SELECT ip FROM stuffToPlot WHERE username = '%s'" % str(username))
        ipretrieve = c3.fetchall()
        ip = str(ipretrieve[0][0].encode('utf-8'))

        c3.execute("SELECT port FROM stuffToPlot WHERE username = '%s'" % str(username))
        portretrieve = c3.fetchall()
        port = str(int(portretrieve[0][0]))
        print ip
        print port

        conn3.close()

        me = usernamestored
        dict = {"profile_username": str(username), "sender": str(me)}
        data = json.dumps(dict)

        url = 'http://' + str(ip) + ':' + str(port) + '/getProfile'

        print "Retrieving profile from " + username
        try:
            returned = urllib2.Request(url, data, {'Content-Type':'application/json'})
            returned2 = urllib2.urlopen(returned).read()

            # file = open('ChatScreen/userprofiles/' + username + '.html', 'w+')
            # file.write(str(returned2))
            # file.close
            jn = json.loads(returned2)
            conn4 = sqlite3.connect('ChatScreen/userprofiles/profiledatabase.db')
            c4 = conn4.cursor()
            c4.execute('CREATE TABLE IF NOT EXISTS profiledata (profile_username TEXT, lastUpdated REAL, fullname TEXT, position REAL, description TEXT, location TEXT, picture TEXT, encoding REAL, encryption REAL, decryptionKey REAL)')
            c4.execute('create unique index if not exists UniqueIndex on profiledata ( profile_username )')
            print jn
            profile_username = None
            lastUpdated = None
            fullname = None
            position = None
            description = None
            location = None
            picture = None
            encoding = None
            encryption = None
            decryptionKey = None
            try:
                profile_username = jn['profile_username']
            except:
                profile_username = username
            try:
                lastUpdated = jn['lastUpdated']
            except:
                pass
            try:
                fullname = jn['fullname']
            except:
                pass
            try:
                position = jn['position']
            except:
                pass
            try:
                description = jn['description']
            except:
                pass
            try:
                location = jn['location']
            except:
                pass
            try:
                picture = jn['picture']
            except:
                pass
            try:
                encoding = jn['encoding']
            except:
                pass
            try:
                encryption = jn['encryption']
            except:
                pass
            try:
                decryptionKey = jn['decryptionKey']
            except:
                pass
            tuple = (profile_username, lastUpdated, fullname, position, description, location, picture, encoding, encryption, decryptionKey)
            tuple2 = (
            lastUpdated, fullname, position, description, location, picture, encoding, encryption,
            decryptionKey, profile_username)
            try:
                c4.execute("INSERT INTO profiledata VALUES(?,?,?,?,?,?,?,?,?,?)", tuple)
            except:
                c4.execute("UPDATE profiledata SET lastUpdated = ?, fullname = ?, position = ?, description = ?, location = ?, picture = ?, encoding = ?, encryption = ?, decryptionKey = ? WHERE profile_username = ?", tuple2)

            conn4.commit()

            c4.execute("select profile_username, lastUpdated, fullname, position, description, location, picture, encoding, encryption, decryptionKey from profiledata where profile_username = ?", (username,))

            html = "<html>"
            for row in c4.fetchall():
                if row[6]:
                    html += "<br>" + "<img src=" + str(row[6]) + """ height="150" width="150" />"""
                if row[0]:
                    html += "<br><br>" + "<b>UPI: </b>" + str(row[0])
                if row[1]:
                    html += "<br>" + "<b>Last Updated: </b>" + str(row[1])
                if row[2]:
                    html += "<br>" + "<b>Full Name: </b>" + str(row[2])
                if row[3]:
                    html += "<br>" + "<b>Position: </b>" + str(row[3])
                if row[4]:
                    html += "<br>" + "<b>Desciption: </b>" + str(row[4])
                if row[5]:
                    html += "<br>" + "<b>Location: </b>" + str(row[5])
                if row[7]:
                    html += "<br>" + "<b>Encoding: </b>" + str(row[7])
                if row[8]:
                    html += "<br>" + "<b>Encryption: </b>" + str(row[8])
                if row[9]:
                    html += "<br>" + "<b>Decryption Key: </b>" + str(row[9])

            html += "</html>"

            html = html.encode('utf-8')
            html_file = open("ChatScreen/userprofiles/" + profile_username + ".html", "w+")
            html_file.write(html)
            html_file.close()

            conn4.close()
            print "Successfully retrieved profile from " + username


        except:
            print "Failed to retrieve profile from " + username

    @cherrypy.expose
    def profileiterate(self):
        t1 = threading.Timer(5, self.profileiterator)
        t1.start()
        raise cherrypy.HTTPRedirect('/chat')

    @cherrypy.expose
    def profileiterator(self):
        myusername = usernamestored
        EncryptedSaltedPassword = encryptedsaltedpasswordstored
        OnlineUsersList = urlopen(
            "http://cs302.pythonanywhere.com/getList?username=" + myusername.lower() + "&password=" + EncryptedSaltedPassword + "&json=1").read()
        jsonloaded = json.loads(OnlineUsersList)
        for key, value in jsonloaded.items():
            self.requestProfile(value['username'])

    @cherrypy.expose
    def editprofile(self, fullname, position, description, location, picture, encoding, encryption, decryptionKey):

        print fullname
        print position
        print description
        print location
        print picture
        print encoding
        print encryption
        print decryptionKey

        me = cherrypy.session.get('username')
        lastUpdated = time.time()

        conn6 = sqlite3.connect('ChatScreen/userprofiles/profiledatabase.db')
        c6 = conn6.cursor()

        tuple = (
        me, lastUpdated, fullname, position, description, location, picture, encoding, encryption, decryptionKey)
        tuple2 = (lastUpdated, fullname, position, description, location, picture, encoding, encryption,
            decryptionKey, me)

        try:
            c6.execute("INSERT INTO profiledata VALUES(?,?,?,?,?,?,?,?,?,?)", tuple)
        except:
            c6.execute("UPDATE profiledata SET lastUpdated = ?, fullname = ?, position = ?, description = ?, location = ?, picture = ?, encoding = ?, encryption = ?, decryptionKey = ? WHERE profile_username = ?", tuple2)
        conn6.commit()

        conn6.close()

        raise cherrypy.HTTPRedirect('/chat')

    @cherrypy.expose
    def editprofilepage(self):
        Page = open("EditProfileScreen/Edit.htm", "r")
        return Page


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self, optional = None, sender = None, filename = None):
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS messages (username TEXT)')

        if optional == None:
            senderclient = cherrypy.request.json['sender']
            messagedata = cherrypy.request.json['message']
            #messagedata = self.injectiondef(messagedata)
        elif optional == 1 or 2 or 3:
            senderclient = sender
            messagedata = filename
            me = cherrypy.session.get('username')

        try:
            c.execute('ALTER TABLE messages ADD COLUMN ' + senderclient + ';')
        except:
            pass

        print senderclient + " sent this: " + messagedata

        currenttime = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        if optional == None:
            messagedata = currenttime + " - " + senderclient + ": " + messagedata
        elif optional == 1:
            messagedata = currenttime + " - " + senderclient + ": " + messagedata + " (Open in Downloads)"
        elif optional == 2:
            messagedata = currenttime + " - " + me + ": " + messagedata + " (File Sent Successfully)"
        elif optional == 3:
            messagedata = currenttime + " - " + me + ": " + messagedata + " (File Failed to Send)"

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
        if optional == None or 1:
            cherrypy.session['notification'] = senderclient;
        self.chat()

        if optional == None:
            return "0"


    @cherrypy.expose
    def ping(self,sender):
        print "ping"
        print sender
        return "0"


    @cherrypy.expose
    def chat(self):

        myusername = cherrypy.session.get('username')
        EncryptedSaltedPassword = cherrypy.session.get('encryptedsaltedpassword')
        if myusername == None:
            myusername = usernamestored
        if EncryptedSaltedPassword == None:
            EncryptedSaltedPassword = encryptedsaltedpasswordstored

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
        data_uri_greendot = open('Resource/greendot.png', 'rb').read().encode('base64').replace('\n', '')
        greendot = '<img src="data:image/png;base64,{0}">'.format(data_uri_greendot)
        data_uri_nodot = open('Resource/nodot.png', 'rb').read().encode('base64').replace('\n', '')
        nodot = '<img src="data:image/png;base64,{0}">'.format(data_uri_nodot)
        data_uri_history = open('Resource/history.png', 'rb').read().encode('base64').replace('\n', '')
        history = '<img src="data:image/png;base64,{0}">'.format(data_uri_history)
        data_uri_notification = open('Resource/notification.png', 'rb').read().encode('base64').replace('\n', '')
        notification = '<img src="data:image/png;base64,{0}">'.format(data_uri_notification)
        data_uri_available = open('Resource/available.png', 'rb').read().encode('base64').replace('\n', '')
        available = '<img src="data:image/png;base64,{0}">'.format(data_uri_available)

        #extracts data from database to output
        c.execute("select username, realname, onlineStatus from stuffToPlot")
        Table = """<html><head></head>"""
        Table += """<div style="background: rgba(0, 0, 0, 0.15);"><bold><font color="white">"""

        Table += """<body><table><col width="1"><col width="1"><col width="1">"""
        Table += "<tr><th>Online</th><th>Status</th><th>Profile</th><th>Client</th></tr>"
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
            if (os.path.isfile("./ChatScreen/userprofiles/" + str(row[0]) + ".html") == True):
                Table += "<th>" + available + "</td>"
            else:
                Table += "<th>" + nodot + "</td>"
            if row[1] == None:
                Table += """<td><a HREF="javascript:includeHTMLmessages('""" + row[0] + """.html')">""" + row[0] + "</a></td></tr>"
            else:
                Table += """<td><a HREF="javascript:includeHTMLmessages('""" + row[0] + """.html')">""" + row[1] + "</a></td></tr>"
        Table += "</table></body>"

        Table += "</font></bold></div></html>"
        Table = Table.encode('utf-8')

        # t = ResumableTimer(5, 'signin')
        # t.start()

        Html_file = open("ChatScreen/Chat_files/onlinetable.html", "w+")
        Html_file.write(Table)
        Html_file.close()
        Templatehtml = open("ChatScreen/Chat.htm", "r")

        conn.close()
        return Templatehtml

    @cherrypy.expose
    def injectiondef(self, input):
        stageone = input.replace("<", "&lt;")
        stagetwo = stageone.replace(">", "&gt;")
        return stagetwo

    @cherrypy.expose
    def testprint(self):
        print 'testprint'

    @cherrypy.expose
    def auth(self):
        global randomstring
        randomstring = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(6)])
        Page = urlopen("https://api-mapper.clicksend.com/http/v2/send.php?method=http&username=gxu630&key=4EE82D0A-511E-A07D-3227-E17C51EB47B2&to=64210602780&message=" + randomstring)
        print "Authenticator code is " + randomstring + ". Awaiting authentication"
        Page = open("AuthScreen/Auth.htm", "r")
        return Page

    @cherrypy.expose
    def submitauth(self, code):
        if code == randomstring:
            raise cherrypy.HTTPRedirect('/chat')
        else:
            self.signout()

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
            global usernamestored
            usernamestored = username
            global encryptedsaltedpasswordstored
            encryptedsaltedpasswordstored = EncryptedSaltedPassword
            global out
            out = 0
            self.update()
            if username == "gxu63":
                raise cherrypy.HTTPRedirect('/auth')

            raise cherrypy.HTTPRedirect('/chat')

        else:
            raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    def update(self):
        if out == 1:
            return
        else:
            username = usernamestored
            EncryptedSaltedPassword = encryptedsaltedpasswordstored
            self.authoriseUserLogin(username, EncryptedSaltedPassword)
            threading.Timer(60.0, self.update).start()
            print "Re-Reported to login server"

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        EncryptedSaltedPassword = cherrypy.session.get('encryptedsaltedpassword')
        Page = urlopen("http://cs302.pythonanywhere.com/logoff?username=" + username.lower() + "&password=" + EncryptedSaltedPassword).read()
        cherrypy.lib.sessions.expire()
        global usernamestored
        usernamestored = None
        global encryptedsaltedpasswordstored
        encryptedsaltedpasswordstored = None
        global out
        out = 1
        global randomstring
        randomstring = None

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
    def Edit_files(self, filename):
        f = open("EditProfileScreen/Edit_files/" + filename, "r")
        data = f.read()
        f.close()
        # return correct mimetype
        cherrypy.response.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
        return data

    @cherrypy.expose
    def Auth_files(self, filename):
        f = open("AuthScreen/Auth_files/" + filename, "r")
        data = f.read()
        f.close()
        # return correct mimetype
        cherrypy.response.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
        return data

    @cherrypy.expose
    def usermessages(self, filename):
        try:
            f = open("ChatScreen/usermessages/" + filename, "r")
            data = f.read()
            f.close()
            # return correct mimetype
            cherrypy.response.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
            return data
        except:
            pass

    @cherrypy.expose
    def userprofiles(self, filename):
        try:
            f = open("ChatScreen/userprofiles/" + filename, "r")
            data = f.read()
            f.close()
            # return correct mimetype
            cherrypy.response.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
            return data
        except:
            pass

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
