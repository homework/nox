'''
The topology panel of the GUI 

@author Kyriakos Zarifis
'''

from PyQt4 import QtGui, QtCore
import math
from random import randint
from communication import TopologyInterface
from views.default import Default_View
import simplejson as json

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Add custom topology views here  (add them in topoWidget.__init__() below)
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from views.monitoring import Monitoring_View
#from views.te import TE_View
#from views.elastictree import ET_View


class Node(QtGui.QGraphicsItem):
    '''
    Interactive Node object
    '''
    Type = QtGui.QGraphicsItem.UserType + 1
    
    def __init__(self, graphWidget, _id, _layer=1):
        QtGui.QGraphicsItem.__init__(self)

        self.graph = graphWidget
        self.topoWidget = self.graph.parent
        self.linkList = []
        self.id = str(_id)
        self.layer = _layer
        self.newPos = QtCore.QPointF()
        self.setFlag(QtGui.QGraphicsItem.ItemIsMovable)
        self.setFlag(QtGui.QGraphicsItem.ItemSendsGeometryChanges)
        self.setZValue(1)
        self.setAcceptHoverEvents(True)
        
        # Node attributes
        self.isUp = True        # up/down state   
        self.showID = True      # Draw NodeId
        self.showNode = True    # Draw Node
        self.isSilent = False   # is switch unresponsive? - draw X
        
        # Switch details menu
        self.switchDetails = QtGui.QMenu('&Switch Details')
        self.switchDetails.addAction('Datapath ID: 0x%s' % self.id)
        self.switchDetails.addAction('Links: ' + str(len(self.linkList)))
        self.switchDetails.addAction('Table Size: '+ '')

        # Switch stats menu
        self.switchStats = QtGui.QMenu('&Get Switch Stats')
    
    def query_port_stats(self):
        self.graph.parent.logDisplay.parent.freezeLog = True
        self.graph.parent.logDisplay\
            .setText( 'Querying port stats for switch: 0x%s' % self.id )
        self.topoWidget.monitoring_view.get_port_stats( self.id )

    def query_table_stats(self):
        self.graph.parent.logDisplay.parent.freezeLog = True
        self.graph.parent.logDisplay\
            .setText( 'Querying table stats for switch: 0x%s' % self.id )
        self.topoWidget.monitoring_view.get_table_stats( self.id )

    def query_agg_stats(self):
        self.graph.parent.logDisplay.parent.freezeLog = True
        self.graph.parent.logDisplay\
            .setText( 'Querying agg stats for switch: 0x%s' % self.id )
        self.topoWidget.monitoring_view.get_aggregate_stats( self.id )

    def query_latest_snapshot(self):
        self.graph.parent.logDisplay.parent.freezeLog = True
        self.graph.parent.logDisplay\
            .setText( 'Querying latest snapshot stats for switch: 0x%s' %\
                          self.id )
        self.topoWidget.monitoring_view.get_latest_snapshot( self.id )

    def query_flow_stats(self):
        self.graph.parent.logDisplay.parent.freezeLog = True
        self.graph.parent.logDisplay\
            .setText( 'Querying flow stats for switch: 0x%s' % self.id )
        self.topoWidget.monitoring_view.get_flow_stats( self.id )

    def query_queue_stats(self):
        self.graph.parent.logDisplay.parent.freezeLog = True
        self.graph.parent.logDisplay\
            .setText( 'Querying queue stats for switch: 0x%s' % self.id )
        self.topoWidget.monitoring_view.get_queue_stats( self.id )

    def filter_map_reduce(self):
        self.filter_topology( "serviceA" )

    def filter_storage(self):
        self.filter_topology( "serviceB" )

    def filter_topology(self, subset_name):
        self.topoWidget.monitoring_view.get_filtered_topology( subset_name )

    def type(self):
        return Node.Type

    def addLink(self, link):
        self.linkList.append(link)
        link.adjust()

    def links(self):
        return self.linkList

        self.setPos(self.newPos)
        return True

    def boundingRect(self):
        adjust = 2.0
        return QtCore.QRectF(-10-adjust, -10-adjust, 23+adjust, 23+adjust)

    def shape(self):
        path = QtGui.QPainterPath()
        path.addEllipse(-10, -10, 20, 20)
        return path

    def paint(self, painter, option, widget):    
        if self.showNode:
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(QtGui.QColor(QtCore.Qt.darkGray).light(25))
            painter.drawEllipse(-9, -9, 20, 20)

            gradient = QtGui.QRadialGradient(-3, -3, 10)
            
            # Choose pattern/color based on who controls drawing
            activeView = self.graph.parent.views[self.graph.drawAccess]
            #pattern = activeView.node_pattern(self) not implemented
            color = activeView.node_color(self)
            if not color:
                color = QtGui.QColor(QtCore.Qt.green)
            
            if option.state & QtGui.QStyle.State_Sunken:
                gradient.setCenter(3, 3)
                gradient.setFocalPoint(3, 3)
                if self.isUp:
                    gradient.setColorAt(1, color.light(100))
                    gradient.setColorAt(0, color.light(30))
                else:
                    gradient.setColorAt(1, QtGui.QColor(QtCore.Qt.gray).light(80))
                    gradient.setColorAt(0, QtGui.QColor(QtCore.Qt.gray).light(20))
            else:
                if self.isUp:
                    gradient.setColorAt(0, color.light(85))
                    gradient.setColorAt(1, color.light(25))
                else:
                    gradient.setColorAt(0, QtGui.QColor(QtCore.Qt.gray).light(60))
                    gradient.setColorAt(1, QtGui.QColor(QtCore.Qt.gray).light(10))

            painter.setBrush(QtGui.QBrush(gradient))
            painter.setPen(QtGui.QPen(QtCore.Qt.black, 0))
            painter.drawEllipse(-10, -10, 20, 20)
        
        if self.showID:
            # Text.
            textRect = self.boundingRect()
            #message = "0x"+self.id#.lstrip("0")
            message = self.id

            font = painter.font()
            font.setBold(True)
            font.setPointSizeF(self.topoWidget.parent.settings.node_id_size)
            painter.setFont(font)
            painter.setPen(QtCore.Qt.gray)
            painter.drawText(textRect.translated(0.1, 0.1), message)
            painter.setPen(QtGui.QColor(QtCore.Qt.gray).light(130))
            painter.drawText(textRect.translated(0, 0), message)
        
        if self.isSilent: # remove
            # Big red X.
            textRect = self.boundingRect()
            message = "X"

            font = painter.font()
            font.setBold(True)
            font.setPointSize(16)
            painter.setFont(font)
            painter.setPen(QtGui.QColor(QtCore.Qt.red).light(30))
            painter.drawText(textRect.translated(4, 2), message)
            painter.setPen(QtGui.QColor(QtCore.Qt.red).light(90))
            painter.drawText(textRect.translated(3, 1), message)

    def itemChange(self, change, value):
        if change == QtGui.QGraphicsItem.ItemPositionChange:
            for link in self.linkList:
                link.adjust()
            self.graph.itemMoved()

        return QtGui.QGraphicsItem.itemChange(self, change, value)

    def mousePressEvent(self, event):
        self.stillHover = False
        self.update()
        QtGui.QGraphicsItem.mousePressEvent(self, event)

    def mouseDoubleClickEvent(self, event):
        self.query_flow_stats()
        QtGui.QGraphicsItem.mouseDoubleClickEvent(self, event)
        
    def mouseReleaseEvent(self, event):
        if event.button() == QtCore.Qt.RightButton:
            popup = QtGui.QMenu()
            popup.addAction("Show &Flow Table", self.query_flow_stats)
            popup.addSeparator()
            
            # Build new switchDetails menu
            self.switchDetails = QtGui.QMenu('&Switch Details')
            self.switchDetails.addAction('Datapath ID: 0x%s' % self.id)
            self.switchDetails.addAction('Links: ' + str(len(self.linkList)/2))
            self.switchDetails.addAction('Table Size: '+ '')
            
            
            popup.addMenu(self.switchDetails)
            popup.addSeparator()
            
            
            
            # Build new stats menu dynamically
            statsMenu = popup.addMenu( '&Get Switch Stats' )
            # Add a bunch of actions to sub menu
            statsMenu.addAction( 'Port Stats', self.query_port_stats )
            statsMenu.addAction( 'Table Stats', self.query_table_stats )
            statsMenu.addAction( 'Aggregate Stats', self.query_agg_stats )
            statsMenu.addAction( 'Flow Stats', self.query_flow_stats )
            statsMenu.addAction( 'Queue Stats', self.query_queue_stats )
            statsMenu.addAction( 'Latest snapshot', \
                                     self.query_latest_snapshot )

            popup.addSeparator()
            #popup.addAction("Bring switch &up", self.alertSwitchUp)
            #popup.addAction("Bring switch &down", self.alertSwitchDown)
            #popup.addAction("Select/deselect switch", self.selectSwitch)
            popup.exec_(event.lastScreenPos())
        self.update()
        QtGui.QGraphicsItem.mouseReleaseEvent(self, event)

    def alertSwitchDown(self):
        ''' when user turns switch off from GUI, sends message
        to dispatch server '''
        mainWindow = self.topoWidget.parent
        sendMsg = SwitchAdminStatus()
        sendMsg.dpid = self.dpid
        sendMsg.admin_up = False
        self.topoWidget.topologyView.topologyInterface.send(sendMsg)
        mainWindow.setStatusTip("Brought down switch %0x" % self.dpid)

    def alertSwitchUp(self):
        ''' when user turns switch on from GUI, sends message
        to dispatch server '''
        mainWindow = self.topoWidget.parent
        sendMsg = SwitchAdminStatus()
        sendMsg.dpid = self.dpid
        sendMsg.admin_up = True
        self.topoWidget.topologyView.topologyInterface.send(sendMsg)
        mainWindow.setStatusTip("Brought down switch %0x" % self.dpid)


    def selectSwitch(self):
        ''' interactive selection of switches by user '''
        if self.layer != HOST_LAYER:
            return
        mainWindow = self.topoWidget.parent
        if self.topoWidget.selectedNode == None:
            self.topoWidget.selectedNode = self
            mainWindow.setStatusTip('Node %d selected' % self.dpid)
        elif self.topoWidget.selectedNode.dpid == self.dpid:
            self.topoWidget.selectedNode = None
            mainWindow.setStatusTip('Node %d deselected' % self.dpid)
        else:
            msg = 'Sending traffic from node ' + self.topoWidget.selectedNode.id \
                    + ' to ' + self.id
            mainWindow.setStatusTip(msg)
            sendMsg = TrafficMsg()
            sendMsg.src = self.topoWidget.selectedNode.dpid
            sendMsg.dst = self.dpid
            self.topoWidget.topologyView.topologyInterface.send(sendMsg)
            self.topoWidget.selectedNode = None
            
    def toggleStatus(self):
        if self.isUp:
            self.alertSwitchDown()
        else:
            self.alertSwitchUp()    
        
    def bringSwitchDown(self):
        self.isUp = False
        for l in self.linkList:
            l.isUp = False
            l.update()
        self.update()

    def bringSwitchUp(self, allLinks = True):
        self.isUp = True
        if allLinks:
            for l in self.linkList:
                l.isUp = True
                l.update()
        self.update()
       
    def hoverEnterEvent(self, event):
        self.stillHover = True
        
        # rebuild switchDetails menu
        self.switchDetails = QtGui.QMenu('&Switch Details')
        self.switchDetails.addAction('Datapath ID: 0x%s' % self.id)
        self.switchDetails.addAction('Links: ' + str(len(self.linkList)/2))
        self.switchDetails.addAction('Table Size: '+ '')
        
        self.hoverPos = event.lastScreenPos() + QtCore.QPoint(10,10)
        self.hoverTimer = QtCore.QTimer()
        self.hoverTimer.singleShot(500, self.showSwitchDetailsMenu)
    
    @QtCore.pyqtSlot()    
    def showSwitchDetailsMenu(self):
        if self.stillHover:
            #pos = self.mapToItem(self,self.pos() + QtCore.QPointF(10,10))
            self.switchDetails.exec_(self.hoverPos)
        
    def hoverLeaveEvent(self, event):
        self.stillHover = False
        self.switchDetails.hideTearOffMenu()
    
        
class Link(QtGui.QGraphicsItem):
    '''
    Interactive Link 
    '''
    Pi = math.pi
    TwoPi = 2.0 * Pi

    Type = QtGui.QGraphicsItem.UserType + 2

    def __init__(self, graphWidget, sourceNode, destNode, sport, dport,\
                        stype, dtype, uid):
        QtGui.QGraphicsItem.__init__(self)
        
        self.graph = graphWidget
        self.topoWidget = self.graph.parent
        self.uid = uid
        self.arrowSize = 10.0
        self.sourcePoint = QtCore.QPointF()
        self.destPoint = QtCore.QPointF()
        self.setFlag(QtGui.QGraphicsItem.ItemIsMovable)
        self.setAcceptedMouseButtons(QtCore.Qt.RightButton)
        self.setAcceptHoverEvents(False)
        self.source = sourceNode
        self.dest = destNode
        self.sport = sport
        self.dport = dport
        self.stype = stype
        self.dtype = dtype
        self.source.addLink(self)
        self.dest.addLink(self)
        self.adjust()
        
        # Link attributes
        self.isUp = True        # up/down state  
        self.showLink = True    # Draw link
        self.showID = False     # Draw link ID   
        self.showPorts = False  # Draw connecting ports  
        
        # Link details menu
        self.linkDetails = QtGui.QMenu('&Link Details')
        self.linkDetails.addAction('Link ID: '+ str(self.uid))
        self.linkDetails.addAction('Ends: '+'dpa:'+str(self.sport)\
                        +'-dpb:'+str(self.dport))
        self.linkDetails.addAction('Capacity: ')

    def type(self):
        return Link.Type

    def sourceNode(self):
        return self.source

    def setSourceNode(self, node):
        self.source = node
        self.adjust()

    def destNode(self):
        return self.dest

    def setDestNode(self, node):
        self.dest = node
        self.adjust()

    def adjust(self):
        if not self.source or not self.dest:
            return

        line = QtCore.QLineF(self.mapFromItem(self.source, 0, 0), self.mapFromItem(self.dest, 0, 0))
        length = line.length()
        
        if length == 0.0:
            return
        
        linkOffset = QtCore.QPointF((line.dx() * 10) / length, (line.dy() * 10) / length)

        self.prepareGeometryChange()
        self.sourcePoint = line.p1() + linkOffset
        self.destPoint = line.p2() - linkOffset

    def boundingRect(self):
        if not self.source or not self.dest:
            return QtCore.QRectF()

        #penWidth = 1
        return QtCore.QRectF(self.sourcePoint,
                             QtCore.QSizeF(self.destPoint.x() - self.sourcePoint.x(),
                                           self.destPoint.y() - self.sourcePoint.y())).normalized()
        '''
        extra = (penWidth + self.arrowSize) / 2.0

        return QtCore.QRectF(self.sourcePoint,
                             QtCore.QSizeF(self.destPoint.x() - self.sourcePoint.x(),
                                           self.destPoint.y() - self.sourcePoint.y())).normalized().adjusted(-extra, -extra, extra, extra)
        '''
        
    def paint(self, painter, option, widget):
        if not self.source or not self.dest:
            return

        # Draw the line itself.
        if self.showLink:
            line = QtCore.QLineF(self.sourcePoint, self.destPoint)
            if line.length() == 0.0:
                return
            
            # Select pen for line (color for util, pattern for state)
            if self.isUp:
                # Choose pattern/color based on who controls drawing
                activeView = self.graph.parent.views[self.graph.drawAccess]
                pattern = activeView.link_pattern(self)
                color = activeView.link_color(self)
                # Highlight when clicked/held
                if option.state & QtGui.QStyle.State_Sunken:
                    color = QtGui.QColor(color).light(256)
                else:
                    color = QtGui.QColor(color).light(100)
            else:
                color = QtCore.Qt.darkGray
                pattern = QtCore.Qt.DashLine
                
            painter.setPen(QtGui.QPen(color, 1, 
                pattern, QtCore.Qt.RoundCap, QtCore.Qt.RoundJoin))
            painter.drawLine(line)
        
        # Draw port numbers
        if self.showPorts:
            offs = 0.2
            offset = QtCore.QPointF(offs,offs)
            sPortPoint = self.sourcePoint + offset 
            dPortPoint = self.destPoint + offset
            textRect = self.boundingRect()
            font = painter.font()
            font.setBold(True)
            font.setPointSize(4)
            painter.setFont(font)
            sx = self.sourcePoint.x()+self.destPoint.x()/12
            sy = self.sourcePoint.y()+self.destPoint.y()/12
            dx = self.sourcePoint.x()/12+self.destPoint.x()
            dy = self.sourcePoint.y()/12+self.destPoint.y()
            painter.setPen(QtCore.Qt.green)
            painter.drawText(sx, sy, str(self.sport))
            painter.drawText(dx, dy, str(self.dport))
            
        # Draw link ID
        if self.showID:
            textRect = self.boundingRect()
            font = painter.font()
            font.setBold(True)
            font.setPointSize(4)
            painter.setFont(font)
            painter.setPen(QtCore.Qt.darkRed)
            painter.drawText((self.sourcePoint.x()+self.destPoint.x())/2, 
                        (self.sourcePoint.y()+self.destPoint.y())/2, str(self.uid))
        
    def mouseReleaseEvent(self, event):
        if event.button() == QtCore.Qt.RightButton:
            popup = QtGui.QMenu()
            popup.addMenu(self.linkDetails)
            popup.addSeparator()
            popup.addAction("Bring link &up", self.alertLinkUp)
            popup.addAction("Bring link &down", self.alertLinkDown)
            popup.exec_(event.lastScreenPos())
        self.update()
        QtGui.QGraphicsItem.mouseReleaseEvent(self, event)

    def alertLinkUp(self):
        ''' when user turns link on from GUI, sends message
        to dispatch server '''
        mainWindow = self.topoWidget.parent
        sendMsg = LinkAdminStatus()
        sendMsg.dpid1 = self.source.dpid
        sendMsg.dpid2 = self.dest.dpid
        sendMsg.port1 = self.sport
        sendMsg.port2 = self.dport
        sendMsg.admin_up = True
        self.topoWidget.topologyView.topologyInterface.send(sendMsg)
        mainWindow.setStatusTip("Brought up link (" + hex(sendMsg.dpid1) \
                + ", " + hex(sendMsg.dpid2) + ")")

    def alertLinkDown(self):
        ''' when user turns link off from GUI, sends message
        to dispatch server '''
        mainWindow = self.topoWidget.parent
        sendMsg = LinkAdminStatus()
        sendMsg.dpid1 = self.source.dpid
        sendMsg.dpid2 = self.dest.dpid
        sendMsg.port1 = self.sport
        sendMsg.port2 = self.dport
        sendMsg.admin_up = False
        self.topoWidget.topologyView.topologyInterface.send(sendMsg)
        mainWindow.setStatusTip("Brought down link (" + hex(sendMsg.dpid1) \
                + ", " + hex(sendMsg.dpid2) + ")")

    def bringLinkUp(self):
        self.isUp = True
        self.update()

    def bringLinkDown(self):
        self.isUp = False
        self.update()

class TopoWidget(QtGui.QWidget):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)
        self.parent = parent
        
        # Handle to logDisplay
        self.logDisplay = self.parent.logWidget.logDisplay
        
        self.topologyView = TopologyView(self)
        
        # Dictionary keeping track of views
        self.views = {}
        # Default view
        default_view = Default_View(self)
        self.views[default_view.name] = default_view
        
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        ### Add custom topology views here
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        self.monitoring_view = Monitoring_View(self)
        #self.te_view = TE_View(self)
        #self.et_view = ET_View(self)
        # Add views to drawAccess dict here
        self.views[self.monitoring_view.name] = self.monitoring_view
        #self.views[self.te_view.name] = self.te_view
        #self.views[self.et_view.name] = self.et_view
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        ### This is the only addition required in this file when adding views
        """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        
        self.changeViewWidget = ChangeViewWidget(self)
  
        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(self.topologyView)
        vbox.addWidget(self.changeViewWidget)

        self.setLayout(vbox)
        self.resize(300, 150)

        self.views["Default"].show()
        
        self.selectedNode = None
        
class ChangeViewWidget(QtGui.QWidget):
    def __init__(self, parent):
        self.parent = parent
        QtGui.QWidget.__init__(self, parent)
        
        # Configure Widget
        # Primary view buttons
        self.viewBtns = []
        for viewName, viewObject in self.parent.views.items():
            button = QtGui.QPushButton(viewName)
            button.setCheckable(True)
            self.viewBtns.append(button)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    viewObject.show)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    self.parent.topologyView.updateAll)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    self.markView)
            self.connect(button, QtCore.SIGNAL('clicked()'),
                    self.notify_backend)
        # Set 'default' button pushed
        self.viewBtns[0].setChecked(True)
        
        # Added by custom views
        self.secondaryBtns = []
        
        # Layout           
        self.grid = QtGui.QGridLayout()
        for i in range(0,len(self.viewBtns)): 
            self.grid.addWidget(self.viewBtns[i], 0, i)
        self.setLayout(self.grid)
        
    def markView(self):
        for b in self.viewBtns:            
            b.setChecked(False)
        self.sender().setChecked(True)
        
    def notify_backend(self):
        return
        msg = GuiViewChanged()
        msg.active_view = str(self.sender().text())
        self.parent.topologyView.topologyInterface.send(msg)
        
                
class TopologyView(QtGui.QGraphicsView):

    updateAllSignal = QtCore.pyqtSignal() 
    
    def __init__(self, parent=None):
        QtGui.QGraphicsView.__init__(self, parent)
        self.parent = parent
        # topologyInterface exchanges json messages with monitoring server
        self.topologyInterface = TopologyInterface(self)
        self.topologyInterface.start()
        #asyncore.loop()
    
        self.setStyleSheet("background: black")
    
        self.topoScene = QtGui.QGraphicsScene(self)
        self.topoScene.setItemIndexMethod(QtGui.QGraphicsScene.NoIndex)
        self.topoScene.setSceneRect(-300, -300, 600, 600)
        self.setScene(self.topoScene)
        self.setCacheMode(QtGui.QGraphicsView.CacheBackground)
        self.setRenderHint(QtGui.QPainter.Antialiasing)
        self.setTransformationAnchor(QtGui.QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QtGui.QGraphicsView.AnchorViewCenter)
        
        self.drawAccess = 'Default'  #(utilization/te/et/etc)

        self.scale(0.9, 0.9)
        self.setMinimumSize(400, 400)
        
        
        # Pan
        self.setDragMode(self.ScrollHandDrag)
        self.setCursor(QtCore.Qt.ArrowCursor)        
        
        # Connect signals to slots
        self.topologyInterface.topology_received_signal[str].connect \
                (self.got_topo_msg)
        self.updateAllSignal.connect(self.updateAll)
        
        # Dictionaries holding node and link QGraphicsItems
        self.nodes = {}
        self.links = {}
        
        # Get an initial current snapshot of the topology
        self.get_topology()
        
        # Subscribe to LAVI for topology changes
        self.subscribe_to_topo_changes()
        
    def subscribe_to_topo_changes(self):
        '''
        Subscribe to LAVI for topology changes
        '''
        msg = {}
        msg["type"] = "lavi"
        msg["command"] = "subscribe"
        msg["node_type"] = "all"
        self.topologyInterface.send(msg)
        
        msg = {}
        msg["type"] = "lavi"
        msg["command"] = "subscribe"
        msg["link_type"] = "all"
        self.topologyInterface.send(msg)
        
        #(see what else. eg. link/node removals?)
        
    def get_nodes(self):
        '''
        Ask lavi for an updated nodes set
        '''
        queryMsg = {}
        queryMsg["type"] = "lavi"
        queryMsg["command"] = "request"
        queryMsg["node_type"] = "all"
        self.topologyInterface.send(queryMsg)
		
    def get_links(self):
        '''
        Ask lavi for an updated links set
        '''
        queryMsg = {}
        queryMsg["type"] = "lavi"
        queryMsg["command"] = "request"
        queryMsg["link_type"] = "all"
        self.topologyInterface.send(queryMsg)
        
    def get_topology(self):
        '''
        Ask lavi for updated nodes and links sets
        '''
        self.get_nodes()
        self.get_links()
        
    def got_topo_msg(self, msg):
        '''
        Handle received links/nodes message 
        '''
        jsonmsg = json.loads(str(msg))
        if "node_id" in jsonmsg:
            if jsonmsg["command"] == "add":
                nodes = jsonmsg["node_id"]
                new_nodes = []
	            # Populate nodes
                for nodeID in nodes:
                    # prepend 0s until len = 12 "CHECK"
                    while len(nodeID) < 12 :
                        nodeID = "0"+nodeID
                    # If nodeItem doesn't already exist
                    if nodeID not in self.nodes.keys():
                        nodeItem = Node(self, nodeID)
                        self.nodes[nodeID] = nodeItem
                        new_nodes.append(nodeItem)  
                self.addNodes(new_nodes)
                self.positionNodes(new_nodes)
            '''
            elif jsonmsg["command"] == "delete":
                nodes = jsonmsg["node_id"]
                deleted_nodes = []
                for nodeID in deleted_nodes:
                    if int(nodeID) in self.nodes.keys():
                        print "deleting node", nodeID 
                        dpid = int(nodeID)
                        del self.nodes[dpid]
            '''
        elif "links" in msg:
            if jsonmsg["command"] == "add":
                links = jsonmsg["links"]
                new_links = []
	            # Populate Links
                linkid = len(self.links)
                for link in links:
                    # If linkItem doesn't already exist
                    # (stupid, expensive full match check as there is no linkID)
                    exists = False
                    for l in self.links.values():
                        if link["src id"]==l.source.id:
                            if link["dst id"]==l.dest.id:
                                if link["src port"]==l.sport:
                                    if link["dst port"]==l.dport:
                                        exists = True
                    if exists:
                        continue   
                    linkid = linkid+1
                    linkItem = Link(self,\
                            self.nodes[link["src id"]],\
                            self.nodes[link["dst id"]],\
                            link["src port"],\
                            link["dst port"],\
                            link["src type"],\
                            link["dst type"],\
                            linkid) 
                    self.links[linkItem.uid] = linkItem
                    new_links.append(linkItem)
                self.addLinks(new_links)
            '''
            elif jsonmsg["command"] == "delete":
                links = jsonmsg["links"]
                for link in links:
                    print "deleting link" 
            '''
                
        
        self.updateAll()
    
    def addNodes(self, new_nodes):
        '''
        Add nodes to topology Scene
        '''
        for nodeItem in new_nodes:
            self.topoScene.addItem(nodeItem)
            
    def addLinks(self, new_links):
        '''
        Add links to topology Scene
        '''
        for linkItem in new_links:
            self.topoScene.addItem(linkItem)
            
    def positionNodes(self, new_nodes):
        '''
        Position nodes according to current loaded layout (or random if none)
        '''
        
        minX, maxX = -300, 300
        minY, maxY = -200, 200
        
        layout = self.parent.parent.settings.current_topo_layout 
        
        print layout
        
        if layout == "random":
            for node in new_nodes:
                node.setPos(randint(minX,maxX), randint(minY,maxY))
        
        else:
            '''
            If node position is described in current layout file, choose that,
            otherwise place randomly
            '''        
            # Optimize: scan file into a dictionary. same for load.
            f = QtCore.QFile("gui/layouts/"+layout)
            f.open(QtCore.QIODevice.ReadOnly)
            for node in new_nodes:
                line = f.readLine()
                found = False
                while not line.isNull():
                    nodeid,x,y = str(line).split()
                    line = f.readLine()
                    if str(node.id) == nodeid:
                        node.setPos(float(x), float(y))
                        found = True
                if not found:
                    node.setPos(randint(minX,maxX), randint(minY,maxY))
            f.close()
        
    def itemMoved(self):
        pass
    
    def disableAllLinks(self):
        for e in self.links.values():
            e.bringLinkDown()
            e.update()

    def enableAllLinks(self):
        for e in self.links.values():
            e.bringLinkUp()
            e.update()

    def disableAllNodes(self):
        for n in self.nodes.values():
            n.bringSwitchDown()
            n.update()

    def enableAllNodes(self):
        for n in self.nodes.values():
            n.bringSwitchUp()
            n.update()

    def updateAll(self):
        '''
        Refresh all Items
        # see if there is a auto way to updateall (updateScene()?)
        '''
        for n in self.nodes.values():
            n.update()
        for e in self.links.values():
            e.update()
            e.adjust()
            
    def keyPressEvent(self, event):
        '''
        Topology View hotkeys
        '''
        key = event.key()
        if key == QtCore.Qt.Key_Plus:
            self.scaleView(1.2)
        elif key == QtCore.Qt.Key_Minus:
            self.scaleView(1 / 1.2)
        elif key == QtCore.Qt.Key_N:
            self.toggleNodes()
        elif key == QtCore.Qt.Key_I:
            self.toggleNodeIDs()
        elif key == QtCore.Qt.Key_K:
            self.toggleLinks()
        elif key == QtCore.Qt.Key_L:
            # LAVI counts a biderctional link as 2 separate links, so IDs overlap
            self.toggleLinkIDs()
            self.updateAll()
        elif key == QtCore.Qt.Key_P:
            self.togglePorts()
            self.updateAll()
        elif key == QtCore.Qt.Key_H:
            self.toggleHosts()
            self.updateAll()
        elif key == QtCore.Qt.Key_R:
            # Refresh topology
            self.get_topology()
        elif key == QtCore.Qt.Key_Space or key == QtCore.Qt.Key_Enter:
            # Redraw topology
            self.positionNodes(self.nodes.values())
            self.updateAll()
        else:
            QtGui.QGraphicsView.keyPressEvent(self, event)
    '''
    Toggle display of drawn items
    '''
    def toggleNodes(self):
        for node in self.nodes.values():
            node.showNode = not node.showNode
            node.update()
            
    def toggleNodeIDs(self):
        for node in self.nodes.values():
            node.showID = not node.showID
            node.update()            

    def toggleLinks(self):
        for link in self.links.values():
            link.showLink = not link.showLink
            link.update()
            
    def toggleLinkIDs(self):
        for link in self.links.values():
            link.showID = not link.showID
            link.update()
            
    def togglePorts(self):
        for link in self.links.values():
            link.showPorts = not link.showPorts
            link.update()
            
    def toggleHosts(self):        
        for node in self.nodes.values():
            if node.layer == 3:
                for l in node.linkList:
                    l.showLink = not l.showLink
                    l.update()
                node.showID = not node.showID
                node.showNode = not node.showNode
                node.update()

    def wheelEvent(self, event):
        '''
        Zoom
        '''
        self.scaleView(math.pow(2.0, event.delta() / 300.0))
        
    def drawBackground(self, painter, rect):
        '''
        Draw background. For now just some text
        '''
        sceneRect = self.sceneRect()
        textRect = QtCore.QRectF(sceneRect.left() -5, sceneRect.top() + 60,
                                 sceneRect.width() - 4, sceneRect.height() - 4)
        message = self.tr("Topology")
        
        font = painter.font()
        font.setPointSize(12)
        painter.setFont(font)
        painter.setPen(QtCore.Qt.darkGray)
        painter.drawText(textRect.translated(0.8, 0.8), message)
        painter.setPen(QtCore.Qt.white)
        painter.setPen(QtGui.QColor(QtCore.Qt.gray).light(130))
        painter.drawText(textRect, message)
        
    def scaleView(self, scaleFactor):
        factor = self.matrix().scale(scaleFactor, scaleFactor).mapRect(QtCore.QRectF(0, 0, 1, 1)).width()

        if factor < 0.07 or factor > 100:
            return

        self.scale(scaleFactor, scaleFactor)
    
    def mouseReleaseEvent(self, event):
        '''
        Show context menu when right-clicking on empty space on the scene.
        '''
        if not self.itemAt(event.pos()):
            if event.button() == QtCore.Qt.RightButton:
                popup = QtGui.QMenu()
                popup.addAction("Save Layout", self.save_layout)
                popup.addAction("Load Layout", self.load_layout)
                popup.addAction("Refresh Topology", self.get_topology)
                popup.exec_(event.globalPos())
        QtGui.QGraphicsView.mouseReleaseEvent(self, event)
    
    def save_layout(self):
        '''
        Saves the current node positioning
        '''
        title = "Specify file to store topology layout"
        filename = QtGui.QFileDialog.getSaveFileName(self,title,"gui/layouts")
        f = QtCore.QFile(filename)
        f.open(QtCore.QIODevice.WriteOnly)
        for node in self.nodes.values():
            line = QtCore.QByteArray(str(node.id)+" "+\
                                    str(round(int(node.x()),-1))+" "+\
                                    str(round(int(node.y()),-1))+" \n")
            f.write(line)
        f.close()
        
        layout = str(filename).split("/")
        layout = layout[len(layout)-1]
        self.parent.parent.settings.set_current_topo_layout(layout)
        
    def load_layout(self):
        '''
        Loads a custom node positioning for this topology
        '''
        title = "Load topology layout from file"
        filename = QtGui.QFileDialog.getOpenFileName(self,title,"gui/layouts")
        f = QtCore.QFile(filename)
        f.open(QtCore.QIODevice.ReadOnly)
        line = f.readLine()
        while not line.isNull():
            nodeid,x,y = str(line).split()
            line = f.readLine()
            if not nodeid in self.nodes:
                print "Layout mismatch (node", nodeid, "exists in conf file but has not been discovered on the network)"
            else:
                self.nodes[nodeid].setX(float(x))
                self.nodes[nodeid].setY(float(y))
        f.close()
        
        layout = str(filename).split("/")
        layout = layout[len(layout)-1]
        self.parent.parent.settings.set_current_topo_layout(layout)
        
        self.updateAll()
