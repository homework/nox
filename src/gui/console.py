'''
Console Widget, used for sending json messages to NOX

@author Kyriakos Zarifis
'''

from PyQt4 import QtGui, QtCore
from communication import ConsoleInterface
import simplejson

class ConsoleWidget(QtGui.QWidget):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)
        self.parent = parent
        
        # Handle to logDisplay
        self.logDisplay = self.parent.logWidget.logDisplay
        
        # Handle to sqldg
        self.curs = self.parent.logWidget.curs
        
        # Configure Widget
        self.label = QtGui.QLabel('Send JSON command to NOX')     
        self.consoleEdit = QtGui.QLineEdit()
        self.consoleEdit.setText("{\"type\":\"lavi\",\"command\":\"request\",\"node_type\":\"all\"}")
        
        '''
        p = QtGui.QPalette()
        p.setColor(QtGui.QPalette.Active, QtGui.QPalette.Base, QtCore.Qt.black)
        p.setColor(QtGui.QPalette.Inactive, QtGui.QPalette.Base, QtCore.Qt.black)
        self.consoleEdit.setPalette(p)
        #self.consoleEdit.setTextColor(QtCore.Qt.darkGreen)
        '''   
        sendCmdBtn = QtGui.QPushButton("&Send")        
        self.connect(sendCmdBtn, QtCore.SIGNAL('clicked()'), self.send_cmd)

        grid = QtGui.QGridLayout()
        grid.setSpacing(10)

        grid.addWidget(self.label, 1, 0)
        grid.addWidget(self.consoleEdit, 2, 0)
        grid.addWidget(sendCmdBtn, 2, 1)
        
        self.setLayout(grid)
        
        self.consoleInterface = ConsoleInterface(self)
        
    def send_cmd(self):
        self.curs.execute("select distinct component from messages")
        comps = []
        for c in self.curs:
            comps.append(str(c)[3:len(str(c))-3])
        if "jsonmessenger" not in comps:
            self.parent.logWidget.logDisplay.parent.freezeLog = True
            self.logDisplay.setText("jsonmessenger is not running")
        else:
            cmd = str(self.consoleEdit.text())
            valid_json = True
            try:
                jsonmsg = simplejson.loads(cmd)
            except:
                self.parent.logWidget.logDisplay.parent.freezeLog = True
                self.logDisplay.setText("invalid json command")
                valid = False
            if valid_json:
                self.consoleInterface.send_cmd(cmd)
                #self.parent.logWidget.logDisplay.parent.freezeLog = False
                            
    def keyPressEvent(self, event):
        key = event.key()

        if key == QtCore.Qt.Key_Enter:
            self.send_cmd()
                
