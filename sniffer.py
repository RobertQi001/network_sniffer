
'''
Created on Apr 22, 2020
Description: A Network Sniffer with GUI of Python based on Winpcap
Environment: python2.7, winpcap
Library required: wxPython, maplotlib
'''

import wx
import wx.lib.mixins.listctrl
import sys, glob, random
import data
from modules import *
import os
import matplotlib
import json
matplotlib.use('WXAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_wxagg import \
    FigureCanvasWxAgg as FigCanvas, \
    NavigationToolbar2WxAgg as NavigationToolbar
import wx.html

class Main(wx.Frame, wx.lib.mixins.listctrl.ColumnSorterMixin):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title = title,size=(800,576))
        self.run = False
        self.devs = [] #devices to capture packets
        self.filters = "" #filters 
        self.captureThread = []
        self.packetCounts = 0
        self.packets = []
        self.packetHeads = []
        self.filename = "" # Filename to save
        self.protocolStats = {} # protocol stats
        self.sourceStats = {}
        self.destinationStats = {}
        self.ipCounts = 0
        self.CreateStatusBar() # A Statusbar in the bottom of the window
        # toolbar = self.CreateToolBar()
        
        
        ## Setting up the menu.
        filemenu = wx.Menu()
        capturemenu = wx.Menu()
        statsmenu = wx.Menu()

        ## wx.ID_ABOUT and wx.ID_EXIT are standard IDs provided by wxWidgets.
        menuSave = filemenu.Append(wx.ID_SAVE, "&Save", " Save captured packet bytes and analyzed information")
        menuSaveAs = filemenu.Append(wx.ID_SAVEAS, "&Save As", "Save packet bytes and analyzed information as another file")
        filemenu.AppendSeparator()
        menuExit = filemenu.Append(wx.ID_EXIT,"&Exit"," Terminate the program")

        menuInterfaces = capturemenu.Append(wx.ID_ANY, "&Interfaces"," Show all the open interfaces")     
        menuStart = capturemenu.Append(wx.ID_ANY, "&Start"," Start capturing packets")
        menuStop = capturemenu.Append(wx.ID_ANY, "&Stop"," Stop capturing packets")
        menuFilters = capturemenu.Append(wx.ID_ANY, "&Filters", " set the filter for capturing packets")
        
        menuProtocol = statsmenu.Append(wx.ID_ANY, "&Protocol", " see the packets protocol stats of current capturing")
        menuIP = statsmenu.Append(wx.ID_ANY, "&IP", " see the IP stats of current capturing")


        ## Creating the menubar.
        menuBar = wx.MenuBar()
        menuBar.Append(filemenu,"&File") # Adding the "filemenu" to the MenuBar
        menuBar.Append(capturemenu,"&Setting")
        menuBar.Append(statsmenu,"&State")

        ## bind menu event
        self.Bind(wx.EVT_MENU, self.OnExit, menuExit)
        self.Bind(wx.EVT_MENU, self.OnInterfaces, menuInterfaces)
        self.Bind(wx.EVT_MENU, self.OnFilters, menuFilters)
        self.Bind(wx.EVT_MENU, self.OnStart, menuStart)
        self.Bind(wx.EVT_MENU, self.OnStop, menuStop)
        self.Bind(wx.EVT_MENU, self.OnSave, menuSave)
        self.Bind(wx.EVT_MENU, self.OnSaveAs, menuSaveAs)
        self.Bind(wx.EVT_MENU, self.OnProtocol, menuProtocol)
        self.Bind(wx.EVT_MENU, self.OnIP, menuIP)
        self.SetMenuBar(menuBar)  # Adding the MenuBar to the Frame content.
     
        
        ## create the list control
        self.list = wx.ListCtrl(self, -1, style=wx.LC_REPORT|wx.LC_HRULES|wx.LC_SINGLE_SEL)


        ## add some columns
        for col, text in enumerate(data.columns):
            self.list.InsertColumn(col, text)
            self.list.SetColumnWidth(col, 130)#set the width of columns
            self.list.SetColumnWidth(5,700)

        self.itemDataMap = {}
        ## initialize the column sorter
        wx.lib.mixins.listctrl.ColumnSorterMixin.__init__(self,
                                                          len(data.columns))
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnPacketListSelect, self.list)

        ## create tree display
        self.tree = wx.TreeCtrl(self,-1)

        self.root = self.tree.AddRoot("Packet Information")

        self.tree.Expand(self.root)

        self.html1 = wx.html.HtmlWindow(self)
        self.html1.SetPage("""<font face="Calibri" size="4">Packet Bytes</font>""")

        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizertext = wx.BoxSizer(wx.HORIZONTAL)
        self.sizertext.Add(self.html1,5,wx.EXPAND)

        boaderstyle = 5
        self.sizer.Add(self.list, 4, wx.EXPAND, boaderstyle)
        self.sizer.Add(self.tree, 2, wx.EXPAND, boaderstyle)
        self.sizer.Add(self.sizertext, 2, wx.EXPAND, boaderstyle)
        self.SetSizer(self.sizer)
        self.Show(True)

    def GetListCtrl(self):
        return self.list
    def AddTreeNodes(self, parentItem, items):
        newItem = self.tree.AppendItem(parentItem, items[0])
        for key in items[1]:
            self.tree.AppendItem(newItem, "%s: %s" % (key,str(items[1][key])))
        self.tree.Expand(newItem)

    def OnExit(self,e):
        self.Close(True)  # Close the frame.

    def OnInterfaces(self,e):
        self.frameInterface = wx.Frame(self, -1, title = "Interfaces")
        panel = wx.Panel(self.frameInterface,-1)
        sizerInterface = wx.BoxSizer(wx.VERTICAL)
        
        i = 0
        self.checkBox = []
        I = Interfaces()
        if len(I)>0:
            for item in I:
                self.checkBox.append(wx.CheckBox(panel, -1, item))
                sizerInterface.Add(self.checkBox[i],1,wx.EXPAND)
                i += 1
        else:
            wx.MessageBox("Can't find network devices, you may need administrator privileges.", "Message",wx.OK)
        for item in self.devs:
            self.checkBox[item-1].SetValue(1)
        buttonInterface = wx.Button(panel, label = 'OK')
        self.Bind(wx.EVT_BUTTON, self.OnButtonInterface, buttonInterface)
        sizerInterface.Add(buttonInterface,0, wx.ALIGN_CENTER|wx.ALL, 5)
        panel.SetSizer(sizerInterface)
        self.frameInterface.Show(True)

    def OnButtonInterface(self,e):
        i = 1
        self.devs = []
        for checkBox in self.checkBox:
            if checkBox.IsChecked():
                self.devs.append(i)
            i += 1
        self.frameInterface.Destroy()
    def AddListItem(self,item):
        index = self.list.InsertStringItem(sys.maxint, str(item[0]))
        if self.packetCounts==1:
            self.firstRow = index
        for col, text in enumerate(item[1:]):
            self.list.SetStringItem(index, col+1, str(text))
            self.list.SetItemData(index, index)
            self.itemDataMap[index] = item
    def PacketCount(self):
        self.packetCounts += 1
        return self.packetCounts
    def OnFilters(self,e):
        self.frameFilters = wx.Frame(self, -1, title = "Filters")
        panel = wx.Panel(self.frameFilters,-1)
        sizerFilters = wx.BoxSizer(wx.HORIZONTAL)
        sizerButtons = wx.BoxSizer(wx.VERTICAL)
        Filterlist = wx.ListCtrl(panel, -1, style=wx.LC_LIST|wx.LC_SINGLE_SEL)
        Filterlist.SetColumnWidth(0, wx.LIST_AUTOSIZE)
        ## add filter options
        for name, value in data.filters:
            item = Filterlist.InsertStringItem(sys.maxint,name)
            if value == self.filters:
                Filterlist.SetItemState(item, wx.LIST_STATE_SELECTED, wx.LIST_STATE_SELECTED)
        
        buttonFiltersOK = wx.Button(panel, label = 'OK')
        buttonFiltersCANCEL = wx.Button(panel, label = 'CANCEL')


        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnFilterListSelect, Filterlist)

        self.Bind(wx.EVT_BUTTON, self.OnButtonOKFilter, buttonFiltersOK)
        self.Bind(wx.EVT_BUTTON, self.OnButtonCANCELFilter, buttonFiltersCANCEL)

        sizerButtons.Add(buttonFiltersOK ,0, wx.ALIGN_CENTER|wx.ALL, 5)
        sizerButtons.Add(buttonFiltersCANCEL, 0, wx.ALIGN_CENTER|wx.ALL, 5)
        sizerFilters.Add(Filterlist,1,wx.EXPAND)
        sizerFilters.Add(sizerButtons,1,wx.ALIGN_CENTER|wx.ALL)
        panel.SetSizer(sizerFilters)
        self.frameFilters.Show(True)

    def OnFilterListSelect(self,e):
        i = e.GetIndex()
        
        self.filtersChoice = data.filters[i][1]
    def OnButtonOKFilter(self,e):
        self.frameFilters.Destroy()
        self.filters = self.filtersChoice

    def OnButtonCANCELFilter(self,e):
        self.frameFilters.Destroy()

    def OnStop(self,e):
        for t in self.captureThread:
            t.stop()
        if self.packetCounts>0:
            self.list.SetItemState(self.firstRow, wx.LIST_STATE_SELECTED, wx.LIST_STATE_SELECTED)
            wx.MessageBox("Packets capturing stopped.", "Message",wx.OK)
        self.run = False

    def OnPacketListSelect(self,e):
        ilist = e.GetIndex()
        i = self.list.GetItemData(ilist)
        page = """<html><font face="Courier New" size="2"><table><tr>"""
        s1 = ""
        for index in range(len(self.packets[i])):
            if index % 16 == 0:
                page += "<td>%s</td></tr><tr><td>%.4x</td><td>" % (s1,index/16)
                s1 = ""
            else:
                if index % 8 == 0:
                    page += "</td><td>"
                    s1 +="</td><td>"
            byte = self.packets[i][index]
            page += "%.2x " % byte
            if byte>32 and byte <127:
                s1 += chr(byte)
            else:
                s1 += "."
        if ((len(self.packets[i])-1) % 16) < 8:
            page+="</td><td>"
            
        page += "</td><td>%s</td></tr></table></font></html>" % s1
        self.html1.SetPage(page)
        self.tree.Delete(self.root)
        self.root = self.tree.AddRoot("Head Information")
        for item in self.packetHeads[i]:
            self.AddTreeNodes(self.root, item)
        self.tree.Expand(self.root)

    def OnStart(self,e):
        if self.run:
            return 0
        if len(self.devs)==0:
            wx.MessageBox("Please selecte interface first.", "Message",wx.OK)
        for d in self.devs:
            self.run = True
            thread = Captures(self,d)
            self.captureThread.append(thread)
            thread.start()
    def SaveFile(self):
        if self.filename:
            out = []
            for i in range(0,self.packetCounts):
                out.append({"Bytes":self.packets[i],"Heads":self.packetHeads[i]})
            f = open(self.filename, 'w')
            try:
                print >> f,json.dumps(out,indent=4)
                wx.MessageBox("Saved in %s." % self.filename, "Message",wx.OK)
            except:
                wx.MessageBox("Save failed.", "Message",wx.OK)
            f.close()
    def OnSave(self, e,):
        if not self.filename:
            self.OnSaveAs(e)
        else:
            self.SaveFile()

    def OnSaveAs(self, e):
        dlg = wx.FileDialog(self, "Save packets as...", os.getcwd(),
                           style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)
        if dlg.ShowModal() == wx.ID_OK:
            filename = dlg.GetPath()
            if not os.path.splitext(filename)[1]:
                filename = filename + '.json'
            self.filename = filename
            self.SaveFile()
        dlg.Destroy()
    def OnProtocol(self,e):
        protocol = []
        counts = []
        details = "\n\nTotal Counts: %d\n" % self.packetCounts
        for p in self.protocolStats:
            details += "%s: %d %.2f%%\n" % (
                p, self.protocolStats[p], float(self.protocolStats[p])*100/self.packetCounts)
            if p in data.abbr:
                protocol.append(data.abbr[p])
            else:
                protocol.append(p)
            counts.append(self.protocolStats[p])
        self.frameProtocol = wx.Frame(self, -1, title = "Protocol summary",size=(400,500))
        panel = wx.Panel(self.frameProtocol,-1)
        sizerProtocol = wx.BoxSizer(wx.VERTICAL)
        fig = Figure()
        canvas = FigCanvas(panel, -1, fig)
        axes = fig.add_subplot(111)
        x = range(len(protocol))
        axes.bar(
            left=x, 
            height=counts, 
            width=0.5, 
            align='center', 
            alpha=0.44,
            picker=5)
        axes.set_ylabel('Counts')
        axes.set_title('Protocol Summary')
        axes.set_xticks(x)
        axes.set_xticklabels(protocol)
        canvas.draw()
        detailText = wx.StaticText(panel, -1, details,size=(400,200))
        
        sizerProtocol.Add(canvas,1,wx.LEFT | wx.TOP | wx.GROW)
        sizerProtocol.Add(detailText,0,wx.EXPAND)
        panel.SetSizer(sizerProtocol)
        self.frameProtocol.Show(True)

    def OnIP(self,e):
        ## display IP stats in HTML table format
        details = """<font face="Calibri" size="4"><b>IP Counts: %d</b><br>""" % self.ipCounts
        details += "<br><b>Source IP stats</b><br><br><table><tr><td>Source IP</td><td>Counts</td><td>%</td></tr>" 
        for p in self.sourceStats:
            details += "<tr><td>%s</td><td>%d</td><td>%.2f%%</td></tr>" % (
                p,self.sourceStats[p],float(self.sourceStats[p])*100/self.ipCounts)
        details += "</table><br><br><b>Destination IP stats</b><br><br><table><tr><td>Source IP</td><td>Counts</td><td>%</td></tr>"
        for p in self.destinationStats:
            details += "<tr><td>%s</td><td>%d</td><td>%.2f%%</td></tr>" % (
                p,self.destinationStats[p],float(self.destinationStats[p])*100/self.ipCounts)
        details += "</table></font>"
        self.frameIP = wx.Frame(self, -1, title = "IP summary",size=(500,500))
        panel = wx.Panel(self.frameIP,-1)
        detailHtml = wx.html.HtmlWindow(panel)
        detailHtml.SetPage(details)
        sizerIP = wx.BoxSizer(wx.VERTICAL)
        sizerIP.Add(detailHtml,1,wx.EXPAND)
        panel.SetSizer(sizerIP)
        self.frameIP.Show(True)



reload(sys) 
sys.setdefaultencoding('utf-8')

app = wx.App(False)
frame = Main(None, "Network Sniffer")
app.MainLoop()
