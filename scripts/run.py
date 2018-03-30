#!/usr/bin/python

import os
import subprocess
import threading
import sys
import time
import argparse
import json

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--inst', metavar='instances', type=str, default="",
                    help='file containing json of all available EC2 instances')
parser.add_argument('--port', metavar='port', type=int, default=8000,
                    help='starting port number for directories and servers')
parser.add_argument('--servers', metavar='#servers', type=int,
                    help='number of physical servers')
parser.add_argument('--gsize', metavar='size', type=int,
                    help='size of each group')
parser.add_argument('--groups', metavar='#groups', type=int,
                    help='number of groups')
parser.add_argument('--clients', metavar='#clients', type=int,
                    help='number of clients')
parser.add_argument('--trustees', metavar='#trustees', type=int,
                    help='number of trustees')
parser.add_argument('--msgs', metavar='#msgs', type=int,
                    help='number of msgs per group')
parser.add_argument('--msize', metavar='size', type=int,
                    help='size of the message')
parser.add_argument('--type', metavar='type', type=int,
                    help='type of network')
parser.add_argument('--mode', metavar='mode', type=int,
                    help='mode of operation')

flags = vars(parser.parse_args(sys.argv[1:]))
if flags['branch'] == -1:
    flags['branch'] = flags['groups']

aws = not flags['inst'] == ''

if aws:
    root = []
    ips = []
    with open(flags['inst']) as inst_file:
        insts = json.load(inst_file)
        for r in insts['Reservations']:
            for inst in r['Instances']:
                try:
                    ip = inst['PrivateIpAddress']
                    try:
                        if inst["Tags"][0]["Value"] == "Root":
                            root.append(ip)
                    except:
                        ips.append(ip)
                except:
                    pass
    print("number of servers in pool:", len(ips), len(root))


storage = '/tmp'
gopath = os.getenv('GOPATH')
src_dir = 'github.com/kwonalbert/atom'

os.system('go install -tags experimental %s/cmd/db' % (src_dir))
os.system('go install -tags experimental %s/cmd/directory' % (src_dir))
os.system('go install -tags experimental %s/cmd/trustee' % (src_dir))
os.system('go install -tags experimental %s/cmd/server' % (src_dir))
os.system('go install -tags experimental %s/cmd/client' % (src_dir))

flag_dir_addr = "--dirAddr 127.0.0.1:%d" % flags['port']
if aws:
    flag_dir_addr = "--dirAddr %s:%d" % (root[0], flags['port'])
flags['port'] += 1

flag_db_addr = "--dbAddr 127.0.0.1:%d" % flags['port']
if aws:
    flag_db_addr = "--dbAddr %s:%d" % (root[0], flags['port'])
flags['port'] += 1

flag_num_clients = "--numClients %d" % flags['clients']
flag_per_group = "--perGroup %d" % flags['gsize']
flag_num_servers = "--numServers %d" % flags['servers']
flag_num_groups = "--numGroups %d" % flags['groups']
flag_num_trustees = "--numTrustees %d" % flags['trustees']
flag_num_msgs = "--numMsgs %d" % flags['msgs']
flag_msg_size = "--msgSize %d" % flags['msize']
flag_mode = "--mode %d" % flags['mode']
flag_net = "--net %d" % flags['type']
flag_server_keys = "--keyFile %s/src/%s/keys/server_keys.json" % (gopath, src_dir)
flag_trustee_keys = "--keyFile %s/src/%s/keys/trustee_keys.json" % (gopath, src_dir)

def localhost(c):
    os.system(c)

def remotehost(dest, c):
    os.system("ssh -o StrictHostKeyChecking=no -i ~/.ssh/emerald.pem %s '%s'" % (dest, c))

dir_flags = " ".join([flag_dir_addr,
                      flag_per_group,
                      flag_num_servers,
                      flag_num_clients,
                      flag_num_groups,
                      flag_num_trustees,
                      flag_num_msgs,
                      flag_msg_size,
                      flag_mode,
                      flag_net,
                      flag_branch])
c = '%s/bin/directory %s' % (gopath, dir_flags)
if aws:
    directory = threading.Thread(target=remotehost, args=(root[0], c,))
else :
    directory = threading.Thread(target=localhost, args=(c,))
directory.start()

time.sleep(1)

c = '%s/bin/db %s' % (gopath, flag_db_addr)
if aws:
    db = threading.Thread(target=remotehost, args=(root[0], c,))
else :
    db = threading.Thread(target=localhost, args=(c,))
db.start()

ts = []
for i in range(flags['trustees']):
    flag_id = "--id %d" % i
    flag_trustee_addr = "--addr 127.0.0.1:%d" % (flags['port'])
    if aws:
        flag_trustee_addr = "--addr %s:%d" % (root[0], flags['port'])
    flags['port'] += 1
    trustee_flags = " ".join([flag_trustee_keys,
                              flag_dir_addr,
                              flag_trustee_addr,
                              flag_id])
    c = '%s/bin/trustee %s' % (gopath, trustee_flags)
    if aws:
        t = threading.Thread(target=remotehost, args=(root[0], c,))
    else:
        t = threading.Thread(target=localhost, args=(c,))
    t.start()
    ts.append(t)

time.sleep(1)

print("Starting servers...")
ss = []
for i in range(flags['servers']):
    flag_addr = "--addr 127.0.0.1:%d" % (flags['port']+i)
    if aws:
        flag_addr = "--addr %s:%d" % (ips[i%len(ips)], flags['port']+i)
    flag_id = "--id %d" % i
    serv_flags = " ".join([flag_server_keys,
                           flag_dir_addr,
                           flag_db_addr,
                           flag_addr,
                           flag_id])
    c = '%s/bin/server %s' % (gopath, serv_flags)
    if aws:
        t = threading.Thread(target=remotehost, args=(ips[i%len(ips)], c,))
    else:
        t = threading.Thread(target=localhost, args=(c,))
    t.start()
    ss.append(t)

time.sleep(0.5)

print("Starting clients...")
cs = []
for i in range(flags['clients']):
    flag_id = "--id %d" % i
    client_flags = " ".join([flag_dir_addr,
                             flag_db_addr,
                             flag_id])

    c = '%s/bin/client %s' % (gopath, client_flags)
    if aws:
        t = threading.Thread(target=remotehost, args=(ips[i%len(ips)], c,))
    else:
        t = threading.Thread(target=localhost, args=(c,))
    t.start()
    cs.append(t)

print("Waiting for completion...")
for t in cs:
    t.join()

if not aws:
    os.system('killall trustee')
    os.system('killall server')
    os.system('killall client')
    os.system('killall directory')
    os.system('killall db')
