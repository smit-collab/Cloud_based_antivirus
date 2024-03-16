from bugdefender.cognitohelper import CognitoHelper
from boto3.dynamodb.conditions import Key
import dbsetup
import boto3
import bugdefender.configure as cfg
import bugdefender.util as util
import sqlite3
import json
import time
import sys
import traceback
import os
import uuid
from boto3.s3.transfer import S3Transfer
from PyQt5 import QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUi

USERNAME = ''
ch = CognitoHelper()


class ScanTableModel(QAbstractTableModel):
    def __init__(self, header):
        super(ScanTableModel, self).__init__()
        self.files = []
        self.header_labels = header

    def data(self, index, role):
        if len(self.files) > 0:
            if role == Qt.DisplayRole:
                # See below for the nested-list data structure.
                # .row() indexes into the outer list,
                # .column() indexes into the sub-list
                # Get the raw value
                value = self.files[index.row()][index.column()]

                if index.column() == 0:
                    value = value.split('/')[-1]
                    return value
                return value

            if role == Qt.DecorationRole:
                value = self.files[index.row()][index.column()]
                if value == 'scanning':
                    return QIcon('resources/loading.png')
                elif value == 'Clean':
                    return QIcon('resources/check.png')
                elif value == 'Infected':
                    return QIcon('resources/cancel.png')
                elif value == 'Error' or value == 'Large File':
                    return QIcon('resources/warning.png')

            if role == Qt.TextAlignmentRole:
                col = index.column()
                if col == 1 or col == 2 or col == 3 or col == 4:
                    # Align right, vertical middle.
                    return Qt.AlignVCenter + Qt.AlignHCenter

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.header_labels[section]
        return QAbstractTableModel.headerData(self, section, orientation, role)

    def rowCount(self, index):
        # The length of the outer list.
        return len(self.files)

    def columnCount(self, index):
        # The following takes the first sub-list, and returns
        # the length (only works if all rows are an equal length)
        return len(self.header_labels)


class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    status = pyqtSignal(object)
    progress = pyqtSignal(int)

class Worker(QRunnable):

    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()

        # Store constructor arguments (re-used for processing)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Add the callback to our kwargs
        self.kwargs['status_callback'] = self.signals.status
        self.kwargs['progress_callback'] = self.signals.progress

    @pyqtSlot()
    def run(self):
        # Retrieve args/kwargs here; and fire processing using them
        try:
            result = self.fn(*self.args, **self.kwargs)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            # Return the result of the processing
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()  # Done

class ProgressPercentage(object):

    def __init__(self, filename, progress_callback):
        self._callback = progress_callback
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0

    def __call__(self, bytes_amount):
        # To simplify, assume this is hooked up to a single filename
        self._seen_so_far += bytes_amount
        percentage = (self._seen_so_far / self._size) * 100
        self._callback.emit(percentage)


class home(QMainWindow):
    def __init__(self):
        super(home, self).__init__()
        loadUi("UI/home.ui", self)
        self.scan_path.setText(QDir.homePath())
        self.scan_path.setReadOnly(True)
        self.browse.clicked.connect(self.browse_directory)
        self.scan.clicked.connect(self.scan_folder)
        self.comboBox.activated.connect(self.handle_account)
        self.progressBar.setAlignment(Qt.AlignCenter)
        self.scancancel.clicked.connect(self.cancel_scan)
        self.scancancel.hide()
        self.progressBar.hide()
        self.progressBar.setRange(0, 100)
        self.filename.hide()
        self.filepath = ''
        self.scanning = False
        self.uploading = False

        header_labels = ['FILE', 'LAST SCAN', 'CLAMAV', 'SOPHOS', 'DR.WEB']
        self.model = ScanTableModel(header_labels)
        self.loadlastscan()
        self.table.setModel(self.model)
        self.table.setColumnWidth(0, 299)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 100)
        self.table.setColumnWidth(3, 100)
        self.table.setColumnWidth(4, 100)
        style = "::section {""background-color: lightblue; }"
        self.table.horizontalHeader().setStyleSheet(style)

        self.threadpool = QThreadPool()
        self.max_size = 104857600  # in bytes
        self.bucket_name = cfg.client['s3_bucket']
        self.table_name = cfg.client['dynamodb_table']
        self.region = cfg.client['aws-region']
        self.userid = os.environ["AWS_IDENTITY_ID"]
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=os.environ["AWS_SESSION_TOKEN"],
        )

        self.dynamodb = boto3.resource(
            'dynamodb',
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=os.environ["AWS_SESSION_TOKEN"],
            region_name=self.region
        )
        self.dtable = self.dynamodb.Table(self.table_name)

    def cancel_scan(self):
        self.scanning = False
        self.uploading = False
        self.scancancel.setText('CANCELING..')

    def loadlastscan(self):
        try:
            with open('data.db', 'r') as f:
                data = json.load(f)
                if data is not None:
                    path = data[0][0].split('/')[:-1]
                    self.scan_path.setText('/'.join(path))
                    self.model.files = data
        except Exception as e:
            print(e)

    def addscanfile(self, filename):
        # self.progressBar.setValue(100)
        s = 'scanning'
        filesize = os.path.getsize(filename)
        if filesize > self.max_size:
            s = 'Large File'
            data = [filename, s, s, s, s]
        else:
            data = [filename, '-', s, s, s]
        self.model.files.append(data)
        # Trigger refresh.
        self.model.layoutChanged.emit()
        self.savescan()
        if self.check_uploaded_but_not_scanned and not self.scanning:
            self.load_scan_result()

    def savescan(self):
        with open('data.db', 'w') as f:
            data = json.dump(self.model.files, f)

    def s3_upload(self, status_callback, progress_callback):
        self.uploading = True
        try:
            userid = self.userid.split(':')[1]

            path = self.scan_path.text()
            for root, dirs, files in os.walk(path):
                for file in files:
                    if not self.uploading:
                        break
                    filepath = os.path.join(root, file)
                    filesize = os.path.getsize(filepath)

                    if not util.is_file_scanned(filepath) and filesize < self.max_size:
                        self.filename.setText(filepath)
                        tempkey = str(uuid.uuid4())
                        key = '/'.join([userid, tempkey])
                        self.upload_file(filepath, key, progress_callback)
                        util.save_file(filepath, tempkey, 'not scanned')
                    status_callback.emit(filepath)
        except Exception as e:
            print(e)

    def upload_file(self, file, key, progress_callback):
        transfer = S3Transfer(self.s3_client)
        transfer.upload_file(
            file, self.bucket_name, key, callback=ProgressPercentage(file, progress_callback))

    def upload_completed(self):
        self.uploading = False
        if self.check_uploaded_but_not_scanned and not self.scanning:
            self.load_scan_result()
        if not self.scanning:
            self.scan.show()
            self.scancancel.hide()
            self.filename.hide()
        self.filename.setText('UPLOADING COMPLETE! SCANNING IN PROGRESS')
        self.progressBar.hide()

    def scan_folder(self):
        self.model.files = []
        self.model.layoutChanged.emit()
        self.scan.hide()
        self.scancancel.show()
        self.progressBar.show()
        self.filename.show()
        # Pass the function to execute
        # Any other args, kwargs are passed to the run function
        worker = Worker(self.s3_upload)
        worker.signals.finished.connect(self.upload_completed)
        worker.signals.status.connect(self.addscanfile)
        worker.signals.progress.connect(self.progressBar.setValue)
        # Execute
        self.threadpool.start(worker)

    def check_uploaded_but_not_scanned(self):
        data = open('data.db', 'r')
        files = json.load(data)
        data.close()
        tobescanned = [f for f in files if f[1] == '-']
        if len(tobescanned) > 0:
            return True
        return False

    def check_scan_result(self, status_callback, progress_callback):
        self.scanning = True
        while self.scanning:
            try:
                self.get_dynamodb_result()
                f = open('data.db', 'r')
                data = json.load(f)
                f.close()
                if data is not None:
                    files = [i[0] for i in data if i[1] == '-']
                    if len(files) == 0:
                        self.scanning = False
                        break
                    elif len(files) > 1:
                        files = tuple(files)
                    else:
                        files.append("")
                        files = tuple(files)

                    sf = util.get_scanned_files(files)
                    #print(sf)
                    if len(sf) > 0:
                        status_callback.emit(sf)
                time.sleep(5)
            except Exception as e:
                print(e)

    def update_scan_model(self, files):
        f = open('data.db', 'r')
        data = json.load(f)
        f.close()
        if data is not None:
            for f in files:
                #file = f[0].replace('/', '\\')
                #print(f[0])
                #print(file)
                for d in range(0, len(data)):
                    #print(data[d][0])
                    if data[d][0] == f[0]:

                        data[d][1] = f[1]
                        data[d][2] = f[2]
                        data[d][3] = f[3]
                        data[d][4] = f[4]
                break
            self.model.files = data
            # Trigger refresh.
            self.model.layoutChanged.emit()
            self.savescan()

    def scan_completed(self):
        self.scanning = False
        if not self.uploading:
            self.scan.show()
            self.scancancel.hide()
            self.filename.setText("SCANNING COMPLETE!")

    def load_scan_result(self):
        scanner = Worker(self.check_scan_result)
        scanner.signals.finished.connect(self.scan_completed)
        scanner.signals.status.connect(self.update_scan_model)
        # Execute
        self.threadpool.start(scanner)

    def get_dynamodb_result(self):
        userid = self.userid.split(':')[1]
        response = self.dtable.query(
            KeyConditionExpression=Key('userid').eq(userid)
        )
        #print(response['Items'])
        self.update_local_database(response['Items'])

    def update_local_database(self, data):
        files = [(f['scanned_on'], f['clamav'], f['sophos'],
                  f['drweb'], f['objectkey']) for f in data]
        util.batch_update_db(files)

    def handle_account(self):
        s = self.comboBox.currentText()
        if s == 'Exit':
            self.exitaction()
        elif s == 'Logout':
            self.logout()
        elif s == 'Change Password':
            change_password_page()

    def exitaction(self):
        self.uploading = False
        self.scanning = False
        sys.exit()

    def logout(self):
        try:
            util.logout_user(USERNAME)
            signin_page()
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Success',
                                  "Successfully Logged out").exec_()
        except Exception as e:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error',
                                  str(e)).exec_()

    def browse_directory(self, button):
        # get download_path from lineEdit
        scan_path = self.scan_path.text()

        # open select folder dialog
        fname = QFileDialog.getExistingDirectory(
            self, 'Select a directory', scan_path)

        if fname:
            # Returns pathName with the '/' separators converted to separators that are appropriate for the underlying operating system.
            # On Windows, toNativeSeparators("c:/winnt/system32") returns
            # "c:\winnt\system32".
            fname = QDir.toNativeSeparators(fname)

        if os.path.isdir(fname):
            self.scan_path.setText(fname)
        # enable when link_lineEdit is not empty and find size of file.


class signin(QDialog):
    def __init__(self):
        super(signin, self).__init__()
        loadUi("UI/signin.ui", self)
        self.signup.clicked.connect(signup_page)
        self.forgotpassword.clicked.connect(forgot_pasword_page)
        self.signin.clicked.connect(self.process_signin)

    def process_signin(self):
        username = self.username.text()
        password = self.password.text()
        if util.is_valid_email(username):
            res = ch.signin(username, password)
            if res == True:
                home_page()
            elif res == 'notconfirmed':
                confirm_signup_page()
                QtWidgets.QMessageBox(
                    QtWidgets.QMessageBox.Critical, 'Error', "User is not confirmed").exec_()

            else:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error',
                                      res).exec_()

        else:
            QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Critical, 'Error', "Invalid Email ID").exec_()


class forgot_password(QDialog):
    def __init__(self):
        super(forgot_password, self).__init__()
        loadUi("UI/forgotpass.ui", self)
        self.sendotp.clicked.connect(self.process_forgot_pass)
        self.signup.clicked.connect(signup_page)

    def process_forgot_pass(self):
        global USERNAME
        username = self.username.text()
        if util.is_valid_email(username):
            USERNAME = username
            res = ch.forgot_password(username)
            if res == True:
                confirm_forgot_password_page()
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Success',
                                      "Please check your Registered email id for validation code").exec_()
            else:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error',
                                      res).exec_()
        else:
            QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Critical, 'Error', "Invalid Email ID").exec_()


class confirm_forgot_password(QDialog):
    def __init__(self):
        super(confirm_forgot_password, self).__init__()
        loadUi("UI/confirmforgotpass.ui", self)
        self.username.setText(USERNAME)
        self.setpassword.clicked.connect(self.set_password)

    def set_password(self):
        username = self.username.text()
        p1 = self.newpassword1.text()
        p2 = self.newpassword2.text()
        otp = self.otp.text()

        if p1 == p2:
            res = ch.confirm_forgot_password(username, p1, otp)
            if res == True:
                signin_page()
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Success',
                                      "Password has been changed successfully, Please Signin").exec_()
            else:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error',
                                      res).exec_()
        else:
            QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Critical, 'Error', "password do not match").exec_()


class signup(QDialog):
    def __init__(self):
        super(signup, self).__init__()
        loadUi("UI/signup.ui", self)
        self.signup.clicked.connect(self.process_signup)
        self.signin.clicked.connect(signin_page)

    def process_signup(self):
        username = self.username.text()
        password1 = self.password1.text()
        password2 = self.password2.text()
        if util.is_valid_email(username):
            if password1 == password2:
                global USERNAME
                USERNAME = username
                res = ch.signup(username, password1)
                if res == True:
                    confirm_signup_page()
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Success',
                                          "Please confirm your signup, check Email for validation code").exec_()
                else:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error',
                                          res).exec_()

            else:
                QtWidgets.QMessageBox(
                    QtWidgets.QMessageBox.Critical, 'Error', "password do not match").exec_()
        else:
            QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Critical, 'Error', "Invalid Email ID").exec_()


class confirm_signup(QDialog):
    def __init__(self):
        super(confirm_signup, self).__init__()
        loadUi("UI/confirmsignup.ui", self)
        self.username.setText(USERNAME)
        self.confirmsignup.clicked.connect(self.process_confirm_signup)
        self.resend.clicked.connect(self.resend_otp)

    def resend_otp(self):
        username = self.username.text()
        res = ch.resend_otp(username)
        if res == True:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Success',
                                  "OTP resent, check Email for validation code").exec_()
        else:
            QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Critical, 'Error', res).exec_()

    def process_confirm_signup(self):
        username = self.username.text()
        otp = self.otp.text()
        res = ch.confirm_signup(username, otp)
        if res == True:
            signin_page()
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Success',
                                  "User verified successfully, Please Signin").exec_()
        else:
            QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Critical, 'Error', res).exec_()


class change_password(QDialog):
    def __init__(self):
        super(change_password, self).__init__()
        loadUi("UI/changepassword.ui", self)
        self.home.clicked.connect(home_page)
        self.changepassword.clicked.connect(self.process_change_pass)

    def process_change_pass(self):
        oldpass = self.oldpassword.text()
        pass1 = self.password1.text()
        pass2 = self.password2.text()
        if pass1 == pass2:
            res = ch.change_password(USERNAME, oldpass, pass1)
            if res == True:
                home_page()
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Success',
                                      "Password changed successfully").exec_()
            else:
                QtWidgets.QMessageBox(
                    QtWidgets.QMessageBox.Critical, 'Error', res).exec_()
        else:
            QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Critical, 'Error', "Password do not match").exec_()


def home_page():
    homep = home()
    widget.addWidget(homep)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def signup_page():
    signupin = signup()
    widget.addWidget(signupin)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def confirm_signup_page():
    csignupin = confirm_signup()
    widget.addWidget(csignupin)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def signin_page():
    signinp = signin()
    widget.addWidget(signinp)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def forgot_pasword_page():
    fpass = forgot_password()
    widget.addWidget(fpass)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def confirm_forgot_password_page():
    cfpass = confirm_forgot_password()
    widget.addWidget(cfpass)
    widget.setCurrentIndex(widget.currentIndex() + 1)


def change_password_page():
    cpass = change_password()
    widget.addWidget(cpass)
    widget.setCurrentIndex(widget.currentIndex() + 1)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    if util.is_connected():
        try:
            USERNAME = util.get_username()
        except sqlite3.OperationalError as e:
            dbsetup.setup_database()

        if util.is_logged():
            res = util.signin_user(ch)
            if res == True:
                mainwindow = home()
            else:
                mainwindow = signin()
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical,
                                      'Error', res).exec_()
        else:
            mainwindow = signin()

        widget = QtWidgets.QStackedWidget()
        widget.addWidget(mainwindow)
        widget.setFixedHeight(600)
        widget.setFixedWidth(800)
        widget.setWindowTitle('BugDefender AntiVirus')
        widget.setWindowIcon(QIcon('resources/bug16.png'))
        widget.show()
        app.exec_()
    else:
        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical,
                              'Error', "No Internet Connection").exec_()
