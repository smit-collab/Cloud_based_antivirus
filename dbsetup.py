import sqlite3


def setup_database():
    conn = sqlite3.connect('bugdefender.db')
    conn.execute('''CREATE TABLE USER
         (USERNAME TEXT PRIMARY KEY NOT NULL,
         PASSWORD TEXT NOT NULL,
         LOGGED INTEGER NOT NULL);''')

    conn.execute('''CREATE TABLE SCAN_RESULT
        (KEY TEXT PRIMARY KEY NOT NULL,
        FILE TEXT NOT NULL,
        LAST_SCAN TEXT,
        CLAMAV TEXT,
        SOPHOS TEXT,
        DRWEB TEXT,
        STATUS TEXT NOT NULL);''')
    conn.close()


#setup_database()
