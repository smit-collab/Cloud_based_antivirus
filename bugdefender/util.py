import socket
import sqlite3
import re
import os


def is_db_exits():
    try:
        conn = sqlite3.connect('bugdefender.db')
        return True
    except sqlite3.OperationalError as err:
        return False


def is_valid_email(email):
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

    if(re.search(regex, email)):
        return True
    else:
        return False


def is_connected():
    try:
        # connect to the host -- tells us if the host is actually
        # reachable
        socket.create_connection(("1.1.1.1", 53))
        return True
    except OSError:
        pass
    return False


def save_user(username, password):
    conn = sqlite3.connect('bugdefender.db')
    cursor = conn.execute("SELECT USERNAME from USER")
    res = cursor.fetchone()
    if res is None:
        query = "INSERT INTO USER (USERNAME, PASSWORD, LOGGED) \
        VALUES ('{}', '{}', 1)".format(username, password)
    else:
        query = "UPDATE USER SET PASSWORD = '{}' WHERE USERNAME= '{}'".format(
            password, username)
    conn.execute(query)
    conn.commit()
    conn.close()


def update_password(username, password):
    conn = sqlite3.connect('bugdefender.db')
    query = "UPDATE USER SET PASSWORD = '{}' WHERE USERNAME= '{}'".format(
        password, username)
    cursor = conn.execute(query)
    conn.commit()
    conn.close()


def logout_user(username):
    os.environ["AWS_ACCESS_KEY_ID"] = ''
    os.environ["AWS_SECRET_ACCESS_KEY"] = ''
    os.environ["AWS_SESSION_TOKEN"] = ''
    conn = sqlite3.connect('bugdefender.db')
    query1 = "DELETE from USER where USERNAME = '{}';".format(username)
    conn.execute(query1)
    conn.commit()
    conn.close()


def signin_user(ch):
    conn = sqlite3.connect('bugdefender.db')
    cursor = conn.execute("SELECT USERNAME, PASSWORD from USER")
    res = cursor.fetchone()
    res = ch.signin(res[0], res[1])
    conn.close()
    return res


def is_logged():
    conn = sqlite3.connect('bugdefender.db')
    status = False
    cursor = conn.execute("SELECT LOGGED from USER")
    res = cursor.fetchone()
    if res is not None and res[0] == 1:
        status = True
    conn.close()
    return status


def get_username():
    conn = sqlite3.connect('bugdefender.db')
    cursor = conn.execute("SELECT USERNAME FROM USER")
    res = cursor.fetchone()
    if res is not None:
        return res[0]
    conn.close()
    return ''


def save_file(filename, key, status):
    filename = filename.replace('\\', '/')
    conn = sqlite3.connect('bugdefender.db')
    query = "INSERT INTO SCAN_RESULT (KEY, FILE, STATUS) \
        VALUES ('{}', '{}', '{}')".format(key, filename, status)
    cursor = conn.execute(query)
    conn.commit()
    conn.close()


def update_file(key, lastscan, clamav, sophos, drweb):
    conn = sqlite3.connect('bugdefender.db')
    query = "UPDATE SCAN_RESULT SET LAST_SCAN = '{}', \
            CLAMAV = '{}', \
            SOPHOS = '{}', \
            DRWEB = '{}', \
            STATUS = 'scanned' \
        WHERE KEY = '{}'".format(lastscan, clamav, sophos, drweb, key)
    cursor = conn.execute(query)
    conn.commit()
    conn.close()


def batch_update_db(files):
    conn = sqlite3.connect('bugdefender.db')
    query = '''UPDATE SCAN_RESULT SET LAST_SCAN = ?,
            CLAMAV = ?,
            SOPHOS = ?,
            DRWEB = ?,
            STATUS = 'scanned'
        WHERE KEY = ?'''
    cursor = conn.executemany(query, files)
    conn.commit()
    conn.close()


def is_file_scanned(file):
    file = file.replace('\\', '/')
    conn = sqlite3.connect('bugdefender.db')
    query = "SELECT * FROM SCAN_RESULT WHERE FILE = '{}'".format(file)
    cursor = conn.execute(query)
    res = cursor.fetchone()
    conn.close()
    if res is None:
        return False
    return True


def get_scanned_files(files):
    files = [f.replace('\\', '/') for f in files]
    conn = sqlite3.connect('bugdefender.db')
    query = '''SELECT FILE, LAST_SCAN, CLAMAV, SOPHOS, DRWEB FROM SCAN_RESULT WHERE FILE IN {} AND STATUS="scanned"'''.format(
        tuple(files))
    cursor = conn.execute(query)
    result = cursor.fetchall()
    return result


#save_file('C:/Users/email/Downloads/bug51.png', 's+fajahah', 'not scanned')
"""conn = sqlite3.connect('bugdefender.db')
query = '''SELECT * FROM SCAN_RESULT'''
cursor = conn.execute(query)
print(cursor.fetchall())
conn.close()"""
# batch_update_db(('2020-11-12', 'clean', 'infected', 'clean',
#                'c899821a-dea1-4119-9c17-5a8c84e41b08'))
# print(is_file_scanned('C:\\Users\\email\\Downloads\\bug51.png'))
#res = get_scanned_files(('C:\\Users\\email\\Downloads\\bug51.png', ''))
# print(res)
