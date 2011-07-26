#!/usr/bin/python
'''
NOX GUI
This file creates the main application window, sets up the layout and invokes
the GUI's widgets.
The left panel (log) is used for displaying context-specific information.
The right panel (topology) is an interactive display of the topology
The bottom right pane (console) is a frontend for communication with
jsonmessenger. 

@author Kyriakos Zarifis
'''

import struct
import sys
import getopt

from PyQt4 import QtGui, QtCore

import gui.log as log
import gui.topology as topology
import gui.console as console
import gui.Popup as Popup
import gui.settings as settings
import signal
       
class MainWindow(QtGui.QMainWindow):
    
    def usage(self):
        """Print usage information
        """
        print "Usage "+sys.argv[0]+" <options> [IP address | default to localhost]"
        print  "Options:"
        print "-h/--help\n\tPrint this usage guide"
        print "-p/--port\n\tPort to connect to"

    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)

        #Parse options and commandline arguments
        try:
            opts, args = getopt.getopt(sys.argv[1:], "hp:",
                                       ["help","port="])
        except getopt.GetoptError:
            print "Option error!"
            self.usage()
            sys.exit(2)
            
        #Get options
        self.noxport = 2703 #messenger port
        for opt,arg in opts:
            if (opt in ("-h","--help")):
                self.usage()
                sys.exit(0)
            elif (opt in ("-p","--port")):
                self.noxport = int(arg)
            else:
                print "Unhandled option :"+opt
                sys.exit(2)

        # Messenger socket:
        if len(args) >= 1:
            self.noxip = args[0]
        else:
            self.noxip = "127.0.0.1"
            
        # Global Settings
        self.settings = settings.Settings(self)

        # Configure layout
        self.setWindowTitle('NOX Graphical User Interface')
        self.resize(1280, 800)
        self.statusBar().showMessage('Ready')        
        self.center()

        self.logWidget = log.LogWidget(self)
        self.left = self.logWidget
        
        self.topoWidget = topology.TopoWidget(self) 
        
        self.consoleWidget = console.ConsoleWidget(self)  
        
        self.rightvbox = QtGui.QVBoxLayout()
        self.rightvbox.addWidget(self.topoWidget)
        self.rightvbox.addWidget(self.consoleWidget)
        self.right = QtGui.QWidget()
        self.right.setLayout(self.rightvbox)
        
        self.splitter = QtGui.QSplitter(QtCore.Qt.Horizontal)
        self.splitter.addWidget(self.left)
        self.splitter.addWidget(self.right)
        
        self.setCentralWidget(self.splitter)
        
        signal.signal(signal.SIGINT, self.sigint_handler)  

        # Actions
        start = QtGui.QAction(QtGui.QIcon('gui/icons/logo.png'), 'Start', self)
        start.setShortcut('Ctrl+S')
        start.setStatusTip('Start NOX')
        self.connect(start, QtCore.SIGNAL('triggered()'), self.start_nox)        
        
        switch_to_log = QtGui.QAction(QtGui.QIcon('gui/icons/log.png'),'Log View',self)
        switch_to_log.setShortcut('Ctrl+1')
        switch_to_log.setStatusTip('Switch to system log view')
        self.connect(switch_to_log, QtCore.SIGNAL('triggered()'), self.show_log)
        
        switch_to_topo = QtGui.QAction(QtGui.QIcon('gui/icons/topo.png'),'Topology View',self)
        switch_to_topo.setShortcut('Ctrl+2')
        switch_to_topo.setStatusTip('Switch to topology view')
        self.connect(switch_to_topo, QtCore.SIGNAL('triggered()'), self.show_topo)                
                
        switch_to_split = QtGui.QAction(QtGui.QIcon('gui/icons/split.png'),'Split View',self)
        switch_to_split.setShortcut('Ctrl+3')
        switch_to_split.setStatusTip('Switch to split view')
        self.connect(switch_to_split, QtCore.SIGNAL('triggered()'), self.show_split)
        
        toggle_console = QtGui.QAction(QtGui.QIcon('gui/icons/split.png'),'Show/Hide Console',self)
        toggle_console.setShortcut('Ctrl+4')
        toggle_console.setStatusTip('Show/Hide Console')
        self.connect(toggle_console, QtCore.SIGNAL('triggered()'), self.toggle_show_console)
        
        exit = QtGui.QAction(QtGui.QIcon('gui/icons/exit.png'), 'Exit', self)
        exit.setShortcut('Ctrl+Q')
        exit.setStatusTip('Exit application')
        self.connect(exit, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
        
        switch_to_dark = QtGui.QAction('Dark',self)
        switch_to_dark.setStatusTip('Switch to dark color theme')
        self.connect(switch_to_dark, QtCore.SIGNAL('triggered()'), self.dark)     
        
        switch_to_bright = QtGui.QAction('Bright',self)
        switch_to_bright.setStatusTip('Switch to bright color theme')
        self.connect(switch_to_bright, QtCore.SIGNAL('triggered()'), self.bright)        
        
        set_node_id_size_small = QtGui.QAction('Small',self)
        set_node_id_size_small.setStatusTip('Set node ID fonts to small')
        self.connect(set_node_id_size_small, QtCore.SIGNAL('triggered()'), \
         self.settings.set_node_id_size_small) 
        
        set_node_id_size_normal = QtGui.QAction('Normal',self)
        set_node_id_size_normal.setStatusTip('Set node ID fonts to small')
        self.connect(set_node_id_size_normal, QtCore.SIGNAL('triggered()'), \
         self.settings.set_node_id_size_normal) 
        
        set_node_id_size_large = QtGui.QAction('Large',self)
        set_node_id_size_large.setStatusTip('Set node ID fonts to small')
        self.connect(set_node_id_size_large, QtCore.SIGNAL('triggered()'), \
         self.settings.set_node_id_size_large) 
        
        self.statusBar()
       
        # Configure Menubar
        menubar = self.menuBar()
        file_menu = menubar.addMenu('&File')
        file_menu.addAction(start)
        file_menu.addAction(exit)
        view_menu = menubar.addMenu('&View')
        view_menu.addAction(switch_to_log)
        view_menu.addAction(switch_to_topo)
        view_menu.addAction(switch_to_split)
        view_menu.addAction(toggle_console)
        id_size_menu = view_menu.addMenu('ID size')
        id_size_menu.addAction(set_node_id_size_small)
        id_size_menu.addAction(set_node_id_size_normal)
        id_size_menu.addAction(set_node_id_size_large)
        components_menu = menubar.addMenu('&Components')
        components_menu.addAction('Installed Components')
        components_menu.addAction('Active Components')
        #'''
        theme_menu = menubar.addMenu('&Colors')
        theme_menu.addAction(switch_to_dark)
        theme_menu.addAction(switch_to_bright)
        #'''
        help_menu = menubar.addMenu('&Help')
        help_menu.addAction('Help')
        help_menu.addAction('About')

        # Configure Toolbar
        toolbar = self.addToolBar('Exit')
        toolbar.addAction(start)
        toolbar.addAction(switch_to_log)
        toolbar.addAction(switch_to_topo)
        toolbar.addAction(switch_to_split)
        toolbar.addAction(exit)
        
        
    def center(self):
        screen = QtGui.QDesktopWidget().screenGeometry()
        size =  self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)
       
    
    def sigint_handler(self, signal, frame):
        sys.exit(0) 
       
    def closeEvent(self, event):
        '''
        reply = QtGui.QMessageBox.question(self, 'Exit NOX',
            "Are you sure to quit?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:
            #self.topoWidget.topologyView.topologyInterface.listener.stop()
            event.accept()
        else:
            event.ignore()
        '''
        print "Exiting."
        #sys.exit(0)
        self.logWidget.logInterface.shutdown()
        #self.logWidget.logInterface.terminate()
        #self.logWidget.logInterface.wait()
        #event.accept()
        
    def start_nox(self):
        popup = Popup.StartComboBox(self)
        popup.exec_()
    
    def show_log(self):
        self.right.hide()
        self.left.show()
        
    def show_topo(self):
        self.right.show()
        self.left.hide()
        
    def show_split(self):
        self.right.show()
        self.left.show()
    
    #'''
    def dark(self):
        # Change Log colors
        self.logWidget.logDisplay.bgColor = QtCore.Qt.black
        self.logWidget.logDisplay.textColor = \
                QtGui.QColor(QtCore.Qt.green).light(85)
        self.logWidget.logDisplay.setColors()
        self.logWidget.logDisplay.setText(self.logWidget.logDisplay.toPlainText())
        
        # Change Topology colors
        self.topoWidget.topologyView.setStyleSheet("background: black")
        # stupid way to refresh background color:
        self.topoWidget.topologyView.scaleView(0.5)
        self.topoWidget.topologyView.scaleView(2)
        
    def bright(self):
        # Change Topology colors
        self.logWidget.logDisplay.bgColor = \
                QtGui.QColor(QtCore.Qt.gray)
        self.logWidget.logDisplay.textColor = QtCore.Qt.black
        self.logWidget.logDisplay.setColors()
        self.logWidget.logDisplay.setText(self.logWidget.logDisplay.toPlainText())
        
        # Change Topology colors
        self.topoWidget.topologyView.setStyleSheet("background: gray") 
        self.topoWidget.topologyView.scaleView(0.5)
        self.topoWidget.topologyView.scaleView(2)
        
    
    def toggle_show_console(self):
        if self.consoleWidget.isHidden():
            self.consoleWidget.show()
        else:
            self.consoleWidget.hide()
                    
app = QtGui.QApplication(sys.argv)
app.setWindowIcon(QtGui.QIcon('gui/icons/logo.ico'))
noxgui = MainWindow()
noxgui.show()
sys.exit(app.exec_())


