#!/usr/bin/env python3
#vulnerable to XSS, SQLi, Command injection


from flask import Flask, render_template,request,redirect,make_response,session
import sqlite3
import os
from cgi import escape

db = "storage.db"
UPLOAD_FOLDER = '/path/to/the/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf'])

app = Flask(__name__)

def allowed_file(filename):
    if('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS):
        return True

@app.route('/')
def main():
    ul = None
    # if user is admin, list all users
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    return render_template('main.html', name='name', users=ul,news=getNews())

def getNews():
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    return c.execute("SELECT * FROM news").fetchall()

@app.route('/news')
def news():
    term = request.args.get('text')
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    print(term)
    c.execute("insert into news (source,text) values (?,?)",('name',term))
    conn.commit()
    return render_template('main.html', name='name',news=getNews())

@app.route('/name',methods=['POST'])
def name():
    name = request.form['name']
    conn = sqlite3.connect('storage.db')
    c=conn.cursor()
    c.execute("UPDATE users SET name= '%s' WHERE email='%s'"%(name,session['username'][2]))
    conn.commit()
    session['username'] = (name,session['username'][1],session['username'][2])
    return render_template('main.html', name='name',news=getNews())


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
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return render_template('upload.html')


if __name__ == '__main__':
    session
    alicehash='123'
    try:
        os.remove(db)
    except OSError:
        pass
    conn = sqlite3.connect(db)
    c=conn.cursor()
    c.execute("create table NEWS(source string, text string)")
    conn.commit()
    app.config.update(SESSION_COOKIE_HTTPONLY=False)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.run(debug=True)
