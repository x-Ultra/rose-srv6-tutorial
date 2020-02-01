#!/usr/bin/python
# coding=utf-8

import os
import shutil
import yaml
import argparse
import sys
#remove directory nodeconf/
if os.path.exists("nodeconf"):
    shutil.rmtree("nodeconf")       
if os.path.exists("ospf.py"):
	os.remove("ospf.py")  

#variable declaration
router_name = {}
router_id = {}
router_interface_name = {},{}
router_interface_ip_addr = {},{}

host_name = {}
host_gw_name = {}
host_ip_addr = {}
host_gw_addr = {}

link_connect = {}

#functions for file creations
def create_hostlinks(h_name, my_net):
    h_name = my_net.addHost(name=str(h_name), cls=BaseNode)

def create_routerlinks(r_name, my_net):
    r_name = my_net.addHost(name=str(r_name), cls=Router)  

#funktions for creating autonomous folders         
def create_router_start(r_name):
	for i in range(0, len(r_name)):
		router_start = ["#!/bin/sh\n\n",
			"BASE_DIR=nodeconf\n","NODE_NAME=" + r_name[i] + "\n","FRR_PATH=/usr/lib/frr\n",
			"sysctl -w net.ipv6.conf.all.forwarding=1\n",
			"echo \"no service integrated-vtysh-config\" >> /etc/frr/vtysh.conf\n",
			"chown frr:frrvty $BASE_DIR/$NODE_NAME\n\n",
			"$FRR_PATH/zebra -f $PWD/$BASE_DIR/$NODE_NAME/zebra.conf -d -z $PWD/$BASE_DIR/$NODE_NAME/zebra.sock -i $PWD/$BASE_DIR/$NODE_NAME/zebra.pid\n",
			"sleep 1\n",
			"$FRR_PATH/ospf6d -f $PWD/$BASE_DIR/$NODE_NAME/ospf6d.conf -d -z $PWD/$BASE_DIR/$NODE_NAME/zebra.sock -i $PWD/$BASE_DIR/$NODE_NAME/ospf6d.pid"]

		os.mkdir(r_name[i])
		os.chdir(r_name[i])
		s = open("start.sh", "w+")
		s.writelines(router_start)
		s.close()
		os.chdir('..')

def create_router_ospf6d(r_name, r_i_name, r_id):
	for i in range(0, len(r_name)):
		router_ospf_1 = ["hostname " + r_name[i] + "\n","password zebra\n",
			"log file nodeconf/" + r_name[i] + "/ospf6d.log\n",
			"\ndebug ospf6 message all\n","debug ospf6 lsa unknown\n",
			"debug ospf6 zebra\n","debug ospf6 interface\n","debug ospf6 neighbor\n",
			"debug ospf6 route table\n","debug ospf6 flooding\n","!\n"]
		
		os.chdir(r_name[i])
		o = open("ospf6d.conf", "w+")
		o.writelines(router_ospf_1)

		for j in range(0, len(r_i_name[i])):
			router_ospf_2 = ["interface " + r_i_name[i][j] + "\n",
				" ipv6 ospf6 network broadcast\n","!\n"]
			o.writelines(router_ospf_2)
		
		router_ospf_3 = ["router ospf6\n", " ospf6 router-id " + r_id[i] + "\n",
			" log-adjacency-changes detail\n", " redistribute connected\n"]
		o.writelines(router_ospf_3)

		for j in range(0, len(r_i_name[i])):
			router_ospf_4 = [" interface " + r_i_name[i][j] + " area 0.0.0.0\n"]
			o.writelines(router_ospf_4)

		router_ospf_5 = ["!\n", "interface lo\n", " ipv6 ospf6 network broadcast\n",
			" no link-detect\n", "!\n", "line vty\n", " exec-timeout 0 0\n", "!"]
		o.writelines(router_ospf_5)
		o.close()
		os.chdir('..')

def create_router_zebra(r_name, r_i_name, r_i_ip):
	for i in range(0, len(r_name)):
		router_zebra_1 = ["! -*- zebra -*-\n\n", "!\n", "hostname " + r_name[i] + "\n",
			"log file nodeconf/" + r_name[i] + "/zebra.log\n", "!\n", "debug zebra events\n",
			"debug zebra rib\n", "!\n"]
		
		os.chdir(r_name[i])
		o = open("zebra.conf", "w+")
		o.writelines(router_zebra_1)

		for j in range(0, len(r_i_name[i])):
			router_zebra_2 = ["interface " + r_i_name[i][j] + "\n",
				" ipv6 address " + r_i_ip[i][j] + "\n","!\n"]
			o.writelines(router_zebra_2)

		router_zebra_3 = ["interface lo\n", " ipv6 address fcff:" + str(i+1) + "::1/128\n",
			"!\n", "ipv6 forwarding\n", "!\n", "line vty\n", "!"]
		o.writelines(router_zebra_3)

		o.close()
		os.chdir('..')


def create_host_start(h_name, h_gw_name, h_ip_addr, h_gw_addr):
	for i in range(0, len(h_name)):
		host_start = ["#!/bin/sh\n\n",
			"BASE_DIR=/home/user/mytests/hosts/nodeconf\n",
			"NODE_NAME=" + h_name[i] + "\n",
			"GW_NAME=" + h_gw_name[i] + "\n",
			"IF_NAME=$NODE_NAME-$GW_NAME \n",
			"IP_ADDR=" + h_ip_addr[i] + "\n",
			"GW_ADDR=" + h_gw_addr[i] + "\n",
			"ip -6 addr add $IP_ADDR dev $IF_NAME \n",
			"ip -6 route add default via $GW_ADDR dev $IF_NAME"]

		os.mkdir(h_name[i])
		os.chdir(h_name[i])

		s = open("start.sh", "w+")
		s.writelines(host_start)
		s.close()
		os.chdir('..')         

def create_python(h_name, r_name, l_connect):
	python_1 = ["#!/usr/bin/python\n\n",
			"import os\n",
			"import shutil\n",
			"from mininet.topo import Topo\n",
			"from mininet.node import Host\n",
			"from mininet.net import Mininet\n",
			"from mininet.cli import CLI\n",
			"from mininet.util import dumpNodeConnections\n",
			"from mininet.link import Link\n",
			"from mininet.log import setLogLevel\n",
			"from mininet.link import TCLink\n\n",
			"BASEDIR = os.getcwd()+\"/nodeconf/\"\n",
			"OUTPUT_PID_TABLE_FILE = \"/tmp/pid_table_file.txt\"\n\n",
			"PRIVDIR = '/var/priv'\n\n",
			"class BaseNode(Host):\n\n",
			"	def __init__(self, name, *args, **kwargs):\n",
	        "		dirs = [PRIVDIR]\n",
	        "		Host.__init__(self, name, privateDirs=dirs, *args, **kwargs)\n",
	        "		self.dir = \"/temp/%s\" %name\n",
	        "		self.nets = []\n",
	        "		if not os.path.exists(self.dir):\n",
        	"			os.makedirs(self.dir)\n\n",
			"	def config(self, **kwargs):\n",
	    	"		#Init steps\n",
	    	"		Host.config(self, **kwargs)\n",
	    	"		# Iterate over the interfaces\n",
	    	"		first = True\n",
	    	"		for intf in self.intfs.itervalues():\n",
		    "			# Remove any configured address\n",
		    "			self.cmd('ifconfig %s 0' %intf.name)\n",
	    	"		# hostnames in /var/mininet/hostname\n",
	    	"		self.cmd(\"echo '\" + self.name + \"' > \"+PRIVDIR+\"/hostname\")\n",
	    	"		if os.path.isfile(BASEDIR+self.name+\"/start.sh\"):\n",
	    	"			self.cmd('source %s' %BASEDIR+self.name+\"/start.sh\")\n\n",
	   		"	def cleanup(self):\n",
        	"		def remove_if_exists (filename):\n",
        	"			if os.path.exists(filename):\n",
        	"				os.remove(filename)\n\n",
	        "		Host.cleanup(self)\n",
	        "		# Rm dir\n",
	        "		if os.path.exists(self.dir):\n",
		    "			shutil.rmtree(self.dir)\n\n",
	        "		remove_if_exists(BASEDIR+self.name+\"/zebra.pid\")\n",
	        "		remove_if_exists(BASEDIR+self.name+\"/zebra.log\")\n",
	        "		remove_if_exists(BASEDIR+self.name+\"/zebra.sock\")\n",
	        "		remove_if_exists(BASEDIR+self.name+\"/ospf6d.pid\")\n",
	        "		remove_if_exists(BASEDIR+self.name+\"/ospf6d.log\")\n\n",
	        "		remove_if_exists(OUTPUT_PID_TABLE_FILE)\n\n",
			"class Router(BaseNode):\n",
	    	"	def __init__(self, name, *args, **kwargs):\n",
	   		"		BaseNode.__init__(self, name, *args, **kwargs)\n\n",
			"# the add_link function creates a link and assigns the interface names\n",
			"# as node1-node2 and node2-node1\n",
			"def add_link (node1, node2):\n",
	    	"	Link(node1, node2, intfName1=node1.name+'-'+node2.name,\n",
	        "				intfName2=node2.name+'-'+node1.name)\n\n",
			"def create_topo(my_net):\n"]
	
	p = open("ospf.py", "w+")   
	p.writelines(python_1)

	for i in range(0, len(h_name)):
		python_2 = ["	" + h_name[i] + " = my_net.addHost(name='" + h_name[i] + "', cls=BaseNode)\n"]
		p.writelines(python_2)

	for i in range(0, len(r_name)):
		python_3 = ["	" + r_name[i] + " = my_net.addHost(name='" + r_name[i] + "', cls=Router)\n"]
		p.writelines(python_3)
  
  	for i in range(0, len(l_connect)):
  		python_4 = ["	add_link(" + l_connect[i][0] + "," + l_connect[i][1] + ")\n"]
		p.writelines(python_4)
	
	python_5 = ["def stopAll():\n",
    "	# Clean Mininet emulation environment\n",
    "	os.system('sudo mn -c')\n",
    "	# Kill all the started daemons\n",
    "	os.system('sudo killall sshd zebra ospfd')\n\n",
	"def extractHostPid (dumpline):\n",
    "	temp = dumpline[dumpline.find('pid=')+4:]\n",
    "	return int(temp [:len(temp)-2])\n\n\n",
	"def simpleTest():\n",
    "	\"Create and test a simple network\"\n\n",
    "	#topo = RoutersTopo()\n",
    "	#net = Mininet(topo=topo, build=False, controller=None)\n",
    "	net = Mininet(topo=None, build=False, controller=None)\n",
    "	create_topo(net)\n\n",
    "	net.build()\n",
    "	net.start()\n\n\n",
    "	print \"Dumping host connections\"\n",
    "	dumpNodeConnections(net.hosts)\n",
    "	#print 'Testing network connectivity'\n",
    "	#net.pingAll()\n\n",
    "	with open(OUTPUT_PID_TABLE_FILE,\"w\") as file:\n",
    "		for host in net.hosts:\n",
    "			file.write(\"%s %d\\n\" % (host, extractHostPid( repr(host) )) )\n\n",
    "	CLI( net ) \n",
    "	net.stop() \n",
    "	stopAll()\n\n\n",
	"if __name__ == '__main__':\n",
    "	# Tell mininet to print useful information\n",
    "	setLogLevel('info')\n",
    "	simpleTest()"]
	p.writelines(python_5)
	p.close()



with open("input-onlineyamltools.yaml", 'r') as stream:
    network_list = yaml.safe_load(stream)

    for task_obj in enumerate(network_list):
        name = task_obj[1]
        for i in range(0, len(network_list[name])):
            if name == "routers":
                router_name[i] = network_list[name][i]["name"]
                router_id[i] = network_list[name][i]["router-id"]
                for j in range(0, len(network_list[name][i]["interfaces"])):
                    router_interface_name[i][j] = network_list[name][i]["interfaces"][j]["name"]
                    router_interface_ip_addr[i][j] = network_list[name][i]["interfaces"][j]["ip_addr"]

            if name == "hosts":
                host_name[i] = network_list[name][i]["name"]
                host_gw_name[i] = network_list[name][i]["gw_name"]
                host_ip_addr[i] = network_list[name][i]["ip_addr"]
                host_gw_addr[i] = network_list[name][i]["gw_addr"]

            if name == "links":
                link_connect[i] = network_list[name][i] 

if not os.path.exists("nodeconf"):
    os.mkdir("nodeconf")                                            # create nodeconf/
    os.chdir("nodeconf/")                                           # go into nodeconf/
    create_router_start(router_name)
    create_router_ospf6d(router_name,router_interface_name, router_id)
    create_router_zebra(router_name, router_interface_name, router_interface_ip_addr)
    create_host_start(host_name, host_gw_name, host_ip_addr, host_gw_addr)
    create_python(host_name, router_name, link_connect)
    shutil.move("./ospf.py", "../ospf.py")