#!/usr/bin/env python3
#vulnerable to XSS, SQLi


from flask import Flask, render_template,request,redirect,make_response,session, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename
import sqlite3
import os
import sys
import hashlib
import time
import re
from cgi import escape
from PyPDF2 import PdfFileReader
import urllib

db = "storage.db"
UPLOAD_FOLDER = '/home/ubuntu/vuln-webapp/uploads'
ALLOWED_EXTENSIONS = set(['pdf'])
app = Flask(__name__)

'''
protected $_expressions = array(
    '/(\/\*.*\*\/)/Us',
    '/(\t)/',
    '/(javascript\s*:)/Usi',
    '/(@import)/Usi',
    '/style=[^<]*((expression\s*?\([^<]*?\))|(behavior\s*:))[^<]*(?=\>)/Uis',
    '/(ondblclick|onclick|onkeydown|onkeypress|onkeyup|onmousedown|onmousemove|onmouseout|onmouseover|onmouseup|onload|onunload|onerror)=[^<]*(?=\>)/Uis',
    '/<\/?(script|meta|link|frame|iframe).*>/Uis',
    '/src=[^<]*base64[^<]*(?=\>)/Uis',
);
'''


'''
Possible ways to bypass:
1. Doesn't check for URL encoded scripts, so <a href="java&#115;cript:alert('xss')">link</a> will work
2. onmouseenter is not blocked so <a onmouseenter="alert('xss')"></a> will work
'''
expressions = (re.compile('(\/\*.*\*\/)', flags=re.A|re.S),
    re.compile('/(\t)'),
    re.compile('(javascript\s*:)', flags=re.A|re.S|re.I),
    re.compile('(@import)', flags=re.A|re.S|re.I),
    re.compile('style=[^<]*((expression\s*?\([^<]*?\))|(behavior\s*:))[^<]*(?=\>)', flags=re.A|re.S|re.I),
    re.compile('(ondblclick|onclick|onkeydown|onkeypress|onkeyup|onmousedown|onmousemove|onmouseout|onmouseover|onmouseup|onload|onunload|onerror)=[^<]*(?=\>)',flags=re.A|re.S|re.I),
    re.compile('<\/?(script|meta|link|frame|iframe).*>', flags=re.A|re.S|re.I),
    re.compile('src=[^<]*base64[^<]*(?=\>)', flags=re.A|re.S|re.I))

def XssFilter(data):
    for i in expressions:
        data = i.sub('', data)
    print("final",data)
    return data

def SQLFilter(email):
    

    return email

def hash(data):
    """ Wrapper around sha224 """
    return hashlib.sha224(data.replace('\n','').encode('ascii')).hexdigest()

def allowed_file(filename):
    if('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS):
        return True

@app.before_request
def check_headers():
    req_headers = request.headers.get("X-Forwarded-Host")
    if req_headers != None:
        try:
            url_val = urllib.request.urlopen(request.headers["X-Forwarded-Host"]).read()
        except:
            pass
    req_headers = request.headers.get("X-Forwarded-Server")
    if req_headers != None:
        try:
            url_val = urllib.request.urlopen(request.headers["X-Forwarded-Server"]).read()
        except:
            pass

@app.route('/')
def main():
    if not 'username' in session:
        return redirect("/login",303)
    ul = None
    # if user is admin, list all users
    if session['username']==('admin','admin','admin'):
        conn = sqlite3.connect('storage.db')
        c=conn.cursor()
        ul = c.execute("SELECT * FROM users").fetchall()
    return render_template('main.html', name=session['username'][0], users=ul,news=getNews(),files=getFiles())

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('form.html')
    elif request.method == 'POST':
        conn = sqlite3.connect('storage.db')
        c=conn.cursor()
        email = request.form['email']        
        password = hash(request.form['password'])
        print("SELECT * FROM users WHERE email='%s' and password='%s'"%(email,password))
        c.execute("SELECT * FROM users WHERE email='%s' and password='%s'"%(email,password))
        # c.execute("SELECT * FROM users WHERE email=(?) and password=(?)", (email,password))
        rval=c.fetchone()
        if email == 'admin@a.com' and password == app.adminhash:
            rval=('admin','admin','admin')
        if rval:
            session['username'] = rval          
            return redirect("/",303)
        else:
            return render_template('form.html', error='Username or password incorrect!')

@app.route('/handler', methods=['POST'])
def handler():
    url = request.form['target']
    rval = urllib.request.urlopen(url).read()
    return render_template('main.html', error3=rval,news=getNews())

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect("/login",303)    

def getNews():
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    return c.execute("SELECT * FROM news").fetchall()

def getFiles():
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    allFiles = c.execute("SELECT * FROM files").fetchall()
    newFileList = []
    for f in allFiles:
        newFileList.append((f[0], f[1].rsplit("-", 1)[0]))
    return newFileList

@app.route('/news')
def news():
    if not 'username' in session:
        return redirect("/login",303)
    term = request.args.get('text')
    print(term)
    term = XssFilter(term)
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    c.execute("insert into news (source,text) values (?,?)",(session['username'][0],term))
    conn.commit()
    return render_template('main.html', name=session['username'][0],news=getNews(),files=getFiles())

@app.route('/name',methods=['POST'])
def name():
    if not 'username' in session:
        return redirect("/login",303)
    name = request.form['name']
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    c.execute("UPDATE users SET name= '%s' WHERE email='%s'"%(name,session['username'][2]))
    conn.commit()
    session['username'] = (name,session['username'][1],session['username'][2])
    return render_template('main.html', name=session['username'][0],error2="Updated username to "+name,news=getNews(),files=getFiles())

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect("/", 303)
        if file and allowed_file(file.filename):
            filename = file.filename
            filesavename = file.filename + "-" + str(int(time.time()))
            try:
                val = os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                mimetype = str(file.content_type)
                print(mimetype)
                if(mimetype == "application/pdf"):
                    try:
                        newpdf = PdfFileReader(file(file, "rb"))
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        conn = sqlite3.connect('storage.db')
                        c=conn.cursor()
                        c.execute("insert into files (source,filename) values (?,?)",(session['username'][0],filesavename))
                        conn.commit()
                    except:
                        print("PDF file not valid")
            except ValueError as e:
                print(e)
                if(str(e) == "embedded null byte"):
                    newf = str(filename.split('\0')[0])
                    print(newf)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], newf))
                else:
                    print("Did nothing")
                    pass

            return render_template('main.html', name=session['username'][0],files=getFiles())
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/ping', methods=['POST'])
def ping():
    cmd = 'ping -c 1 '+ request.form['target']
    if ";" in cmd:
        cmd_list = cmd.split(";")
        stream = os.popen(cmd_list[0])
        rval = stream.read()
    elif "|&" in cmd:
        cmd = cmd.replace("|&", "|")
        stream = os.popen(cmd)
        rval = stream.read()
    elif "|" in cmd:
        cmd_list = cmd.split("|")
        stream = os.popen(cmd_list[0])
        rval = stream.read()
    elif "&" in cmd:
        cmd_list = cmd.split("&&")
        stream = os.popen(cmd_list[0])
        rval = stream.read()
    else:
        stream = os.popen(cmd)
        rval = stream.read()
    return render_template('main.html', error4=rval)

if __name__ == '__main__':

    with open('secrets','r') as f:
        s = f.readlines()
    app.secret_key = s[0].replace('\n','')
    app.adminhash=hash(s[1])
    alicehash=hash(s[2])
    
    try:
        os.remove(db)
    except OSError:
        pass
    conn = sqlite3.connect(db)
    c=conn.cursor()
    c.execute("create table NEWS(source string, text string)")
    c.execute("create table FILES(source string, filename string)")
    c.execute("create table USERS(name string, password string, email string)")
    c.execute("insert into users (email, name,password) values ('alice@alice.com','alice','"+alicehash+"')")
    conn.commit()
    app.config.update(SESSION_COOKIE_HTTPONLY=False)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.run(host='0.0.0.0', debug=True)
 
