from flask import request
from IVANDKEY import *
from flask import Flask,render_template,redirect,url_for,session,flash,send_file
from datetime import date
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import MySQLdb
import os
from base64 import b64encode, b64decode, urlsafe_b64decode, urlsafe_b64encode
from werkzeug.security import generate_password_hash, check_password_hash

app=Flask(__name__)

app.secret_key=os.urandom(24)

conn = MySQLdb.connect(host="localhost",user="root",password="",db="myapp")
cursor=conn.cursor()
APP_ROOT=os.path.dirname(os.path.abspath(__file__))


@app.route('/adminlogin')
def adminlogin():
    return render_template('adminlogin.html')

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/home')
def home():
    if 'id' in session:
        id = session ['id']
        cursor.execute("SELECT username,email FROM user WHERE id=%s",(id,))
        user=cursor.fetchall()
        email=user[0][1]
        cursor.execute('SELECT fid,file_name,upload_date FROM file where uemail=%s',(email,))
        filedata=cursor.fetchall()
        cursor.execute('SELECT did,file_name,datee FROM download where uemail=%s', (email,))
        download_data = cursor.fetchall()
        cursor.execute('SELECT fid FROM request WHERE uemail=%s AND permission = %s',(email,"YES",))
        fid=cursor.fetchall()
        if fid:
            query=("SELECT fid,file_name,keyy from file where fid IN ({})".format(','.join(['%s'] * len(fid))))
            cursor.execute(query,fid)
            key_details=cursor.fetchall()
            return render_template("home.html",name=user,files=filedata,accepted=key_details,download=download_data)
        else:
            return render_template("home.html",name=user,files=filedata,download=download_data)
    else:
        return redirect('/')

@app.route('/adminhome')
def adminhome():
    if 'aid' in session:

        cursor.execute('SELECT fid,file_name,uemail,upload_date FROM file')
        filedata = cursor.fetchall()
        cursor.execute('SELECT * FROM user')
        all_data=cursor.fetchall()
        cursor.execute('SELECT * FROM request')
        req_data = cursor.fetchall()
        cursor.execute('SELECT * FROM download')
        down_data = cursor.fetchall()
        return render_template("adminhome.html",users=all_data,files=filedata,reqs=req_data,downs=down_data)
    else:
        return redirect('/admin')

@app.route('/login_validation',methods={"POST"})
def login_validation():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

    cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
    users = cursor.fetchone()
    if users and check_password_hash(users[3], password):
        if users[5]=="authorised":
            if len(users) > 0:
                session['id'] = users[0]
                session['loggedin'] = True
                return redirect('/home')
        else:
            flash("User not authorised")
            return redirect('/')
    else:
         flash("Incorrect Email/Password")
         return redirect('/')


@app.route('/adminlogin_validation',methods={"POST"})
def adminlogin_validation():
    if request.method == "POST":
         aemail=request.form.get('aemail')
         apassword = request.form.get('apassword')

    cursor.execute('SELECT * FROM admin WHERE aemail = %s', (aemail,))
    admin=cursor.fetchone()

    if admin and check_password_hash(admin[2],apassword):
         if len(admin)>0:
            session['aid']=admin[0]
            session['loggedin'] = True

            return redirect('/adminhome')
    else:
        flash("Incorrect email/password")
        return redirect('/adminlogin')

@app.route('/add_user',methods={"POST"})
def add_user():
    username=request.form.get('uname')
    email = request.form.get('uemail')
    password = generate_password_hash(request.form.get('upassword'))
    now=date.today()


    cursor.execute('INSERT INTO user VALUES (NULL, %s, %s, %s, %s,%s)', (username, email,password,now,'unauthorised'))
    conn.commit()
    return redirect('/')

@app.route('/add_admin',methods={"POST"})
def add_admin():

    aemail = request.form.get('uemail')
    apassword = generate_password_hash(request.form.get('upassword'))


    cursor.execute('INSERT INTO admin VALUES (NULL, %s, %s)', (aemail, apassword,))
    conn.commit()
    return "admin added successfully"


@app.route('/action/<uid>/',methods={"POST","GET"})
def action(uid):

    cursor.execute('SELECT  status FROM user where  id=%s',(uid,))
    status=cursor.fetchone()
    print(status)
    if(status[0]=="unauthorised"):
        cursor.execute("UPDATE user SET status = 'authorised' WHERE id = %s",(uid,))
    if (status[0] == "authorised"):
        cursor.execute("UPDATE user SET status = 'unauthorised' WHERE id = %s",(uid,))
    conn.commit()
    return redirect(url_for('adminhome'))

@app.route('/request_acc/<fid>/',methods={"POST","GET"})
def request_acc(fid):

    cursor.execute('SELECT  fid,file_name,uemail FROM file where  fid=%s',(fid,))
    req_file=cursor.fetchone()
    print(req_file)
    cursor.execute("INSERT INTO request VALUES (NULL,%s,%s,%s,%s,%s)",(req_file[0],req_file[1],req_file[2],"NO","NO"))
    conn.commit()
    flash("REQUEST WAS SENT SUCCESSFULLY")
    return redirect(url_for('home'))

@app.route('/delete_file/<fid>/',methods={"POST","GET"})
def delete_file(fid):

    cursor.execute("DELETE FROM file WHERE fid=%s",(fid,))
    cursor.execute("DELETE FROM request WHERE fid=%s",(fid,))
    cursor.execute("DELETE FROM download WHERE fid=%s", (fid,))
    conn.commit()
    flash("FILE DELETED SUCCESSFULLY")

    return redirect(url_for('home'))


@app.route('/areq/<rid>/',methods={"POST","GET"})
def areq(rid):
    print(rid)
    cursor.execute('SELECT  permission,fid FROM request where  rid=%s',(rid,))
    status=cursor.fetchone()
    print(status)
    if(status[0]=="NO"):
        cursor.execute("UPDATE request SET permission = 'YES' WHERE rid = %s",(rid,))
        cursor.execute("SELECT uemail,keyy FROM file WHERE fid=%s",(status[1],))
        sender=cursor.fetchone()
        print(sender)
        flash("REQUEST WAS ACCEPTED")
        conn.commit()
    return redirect(url_for('adminhome'))


@app.route('/ulogout')
def ulogout():
    session.pop('loggedin',None)
    session.pop('id',None)
    return redirect(url_for('login'))


@app.route('/alogout')
def alogout():
    session.pop('loggedin',None)
    session.pop('aid',None)
    return redirect(url_for('adminlogin'))

@app.route('/upload_file', methods={'POST'})
def upload_file():

    filename=request.form.get('filename')
    if 'id' in session:
        id=session['id']
        cursor.execute('SELECT email FROM user Where id =%s',(id,))
        email=cursor.fetchone()
        print(email)
        now = date.today()
        ff=request.files['file']
        data=ff.read()
        cursor.execute("INSERT INTO  file (fid,uemail,file_name,fdata,upload_date) VALUES(NULL ,%s,%s,%s,%s)",(email,filename,data,now))
        conn.commit()
        div(email, filename)
        flash("FILE UPLOADED SUCCESSFULLY")
        return redirect('/home')
    else:
        return 'ERROR'

def div(email,filename):
        cursor.execute("SELECT fdata FROM file WHERE uemail=%s AND file_name=%s",(email,filename,))
        con=cursor.fetchone()
        cursor.execute("SELECT fid FROM file WHERE uemail=%s AND file_name=%s", (email, filename,))
        fdata = cursor.fetchone()
        count=0
        part1=''
        part2=''
        part3=''
        str=con[0]
        print(str)
        for char in str:
            count += 1
        k = 0
        print(count)
        limit = int(count / 3)
        print(limit)
        for i in range(0, 3):
            ctr = 0
            for j in range(k, count):
                k += 1
                if(i==0):
                    part1+=str[j]
                    ctr += 1
                    if (ctr == limit and i != 2):
                        print(part1)
                        cursor.execute("UPDATE file SET part1=%s WHERE fid=%s",(part1,fdata))
                        break
                if (i == 1):
                    part2 += str[j]
                    ctr += 1
                    if (ctr == limit and i != 2):
                        cursor.execute("UPDATE file SET part2=%s WHERE fid=%s", (part2, fdata))
                        break
                if (i == 2):
                    part3 += str[j]
                    ctr += 1
            cursor.execute("UPDATE file SET part3=%s WHERE fid=%s", (part3, fdata))
        conn.commit()
        encrypt(fdata)

def encrypt(fid):
    iv1,iv2=generateIV()
    key1,key2=generatekey()
    print(iv1, iv2)
    print(key1,key2)
    secret_info= (key1)+b":::::"+(key2)+b":::::"+(iv1)+b":::::"+(iv2)
    content=Hybridencryptkey(secret_info,fid)
    cursor.execute("UPDATE file  SET edata=%s WHERE fid= %s",(content,fid))
    conn.commit()
    for i in range(0,3):
        if i % 3 == 0:
            AES(key1,iv1,fid)
        elif i % 3 == 1:
            TrippleDES(key1,iv2,fid)
        else:
            EFernet(key2,fid)
    conn.commit()



def Hybridencryptkey(secret_info,fid):
    key = Fernet.generate_key()
    print(key)
    print(type(key),"key")
    cursor.execute("UPDATE file SET keyy=%s WHERE fid=%s",(key,fid))
    conn.commit()
    fer = Fernet(key)
    content = secret_info
    content = fer.encrypt(content)
    return content

def AES(key,iv,fid):
    cursor.execute("SELECT part1 FROM file WHERE fid=%s",(fid))
    content=cursor.fetchone()
    data=content[0]
    data=data.encode()
    b=len(data)
    if(b%16!=0):
        while(b%16!=0):
            data+=" ".encode()
            b=len(data)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    cont = encryptor.update(data) + encryptor.finalize()
    print(cont,"AES")
    cont=urlsafe_b64encode(cont)
    print(cont)
    cursor.execute("UPDATE file set epart1=%s WHERE fid=%s",(cont,fid,))

def TrippleDES(key,iv,fid):
    cursor.execute("SELECT part2 FROM file WHERE fid=%s",(fid))
    data=cursor.fetchone()
    content=data[0]
    content=content.encode()
    b=len(content);
    if(b%8!=0):
        while(b%8!=0):
            content+=" ".encode()
            b=len(content);
    backend = default_backend();
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend);
    encryptor = cipher.encryptor();
    cont = encryptor.update(content) + encryptor.finalize();
    cont = urlsafe_b64encode(cont)
    cursor.execute("UPDATE file SET epart2=%s WHERE fid=%s", (cont,fid))

def EFernet(key,fid):
    cursor.execute("SELECT part3 FROM file WHERE fid=%s",(fid))
    data = cursor.fetchone()
    content = data[0]
    content=content.encode()
    fer = Fernet(key)
    content=fer.encrypt(content)
    content = urlsafe_b64encode(content)
    print(content,"fernet")
    cursor.execute("UPDATE file SET epart3=%s WHERE fid=%s", (content,fid))

@app.route('/get_download_data/<fid>', methods={"POST","GET"})
def get_download_data(fid):
    cursor.execute("SELECT (keyy) FROM file WHERE fid=%s",(fid,))
    keyy=cursor.fetchone()[0]
    keyy=bytes(keyy.strip(),'utf-8')
    if keyy:
        cursor.execute("SELECT (edata) FROM file WHERE fid=%s",(fid,))
        edata=cursor.fetchone()[0]
        edata = bytes(edata.strip(), 'utf-8')
        secret_info=Hybriddecryptkey(edata,keyy)
        content = secret_info.split(b":::::")
        for i in range(0, 3):
            if i % 3 == 0:
                con1=DAES(content[0],content[2],fid)
            elif i % 3 == 1:
                con2=DTrippleDES(content[0],content[3],fid)
            else:
                con3=DFernet(content[1],fid)
        print(con1,con2)
        con1=str(con1.strip(b' '),'utf-8')
        print(con1)
        con2=str(con2.strip(b' '),'utf-8')
        print(con2)
        main_con=con1+con2+con3
        print(main_con)
        cursor.execute("UPDATE file set fdata=%s WHERE fid=%s",(main_con,fid,))
        cursor.execute("select file_name,fdata FROM file WHERE fid=%s",(fid,))
        download=cursor.fetchone()
        f=open('app.txt','w')
        f.write(download[1])
        f.close()
        cursor.execute("select uemail from file where fid=%s",(fid,))
        email=cursor.fetchone()[0]
        now=date.today()
        cursor.execute("INSERT INTO download(did,fid,file_name,uemail,datee) VALUES(NULL,%s,%s,%s,%s)",(fid,download[0],email,now,))
        q1=cursor.execute("UPDATE request set download = 'YES' where fid=%s",(fid,))
        q2=cursor.execute("DELETE FROM request WHERE fid=%s AND download=%s",(fid,'YES'))
        print(q1,q2)
        conn.commit()
        return send_file('app.txt',attachment_filename=download[0],as_attachment=True)

    flash("FILE DOWNLOADED")
    return redirect('/home')

def Hybriddecryptkey(edata,keyy):
    fer = Fernet(keyy)
    content=fer.decrypt(edata)
    return content

def DAES(key,iv,fileid):
    cursor.execute("SELECT epart1  FROM file WHERE fid=%s",(fileid,))
    content = cursor.fetchone()[0]
    content=urlsafe_b64decode(content)
    print(content)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    content=decryptor.update(content) + decryptor.finalize()
    return content

def DTrippleDES(key,iv,fid):
    cursor.execute("SELECT epart2 FROM file WHERE fid=%s",(fid,))
    content = cursor.fetchone()[0]
    content = urlsafe_b64decode(content)
    backend = default_backend()
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    content=decryptor.update(content) + decryptor.finalize()
    return content

def DFernet(key,fid):
    cursor.execute("SELECT part3 FROM file WHERE fid=%s",(fid,))
    content = cursor.fetchone()[0]
    return content

if __name__=="__main__":
    app.run(debug=True)
