import argparse
import os
import sys
import pyshark
import statistics
import glob
import csv
import itertools

# a fork of https://github.com/AAGiron/tls-handshake-analyzer/ with performance optimizations

def exec(cap, algo):
    time_ua_both = []
    time_op_rp = []

    matches_ua_both = {}
    matches_op_rp = {}

    for idx, pkt in enumerate(cap):
        if not hasattr(pkt, 'tls'):
            continue
            
        if not hasattr(pkt.tls, 'record'):
            continue

        op_rp = not (pkt.ip.src.startswith("192.") or pkt.ip.dst.startswith("192."))
            
        if isinstance(pkt.tls.record, list):
            handshake_type = [int(record.handshake.type) for record in pkt.tls.record if hasattr(record, 'handshake') and hasattr(record.handshake, 'type')]
        elif hasattr(pkt.tls.record, 'handshake'):
            #All handshakes should have a type... but some don't
            if not hasattr(pkt.tls.record.handshake, 'type'):
                continue
                
            handshake_type = [int(pkt.tls.record.handshake.type)]
        
        #Client Hello
        if handshake_type == [1]:
            if int(pkt.tcp.seq) == 1 and (int(pkt.tcp.dstport) == 443 or int(pkt.tcp.dstport) == 8080):
                key = (int(pkt.tcp.seq_raw), int(pkt.tcp.ack_raw))
                
                (matches_op_rp if op_rp else matches_ua_both)[key] = (pkt, )
            
        #Finished
        elif handshake_type == [20]:
            key = (int(pkt.tcp.seq_raw) - int(pkt.tcp.seq) + 1, int(pkt.tcp.ack_raw) - int(pkt.tcp.ack) + 1)
            
            if key in (matches_op_rp if op_rp else matches_ua_both) and (int(pkt.tcp.dstport) == 443 or int(pkt.tcp.dstport) == 8080):
                first = (matches_op_rp if op_rp else matches_ua_both)[key][0]        
                (matches_op_rp if op_rp else matches_ua_both)[key] = (first, pkt)
                
                time = 1000 * (float(pkt.sniff_timestamp) - float(first.sniff_timestamp))
                
                #if not op_rp:
                #    print(time) 
                    
                del (matches_op_rp if op_rp else matches_ua_both)[key]
                
                #sometimes a non captured finish matches a finish from waaaaaay later, which messes everything... or more likely a timeout that was handled in the application
                if time < 1000: # this is 1 seconds -> timeout in the app is 1 second
                    (time_op_rp if op_rp else time_ua_both).append(time)
                  
    print(f"Algo: {algo}")  
    print("Matches op-rp: %d" % len(time_op_rp))
    print("Not Matches op-rp: %d" % len(matches_op_rp))

    print()
    print("Matches ua-rp or ua-op: %d" % len(time_ua_both))
    print("Not Matches ua-rp or ua-op: %d" % len(matches_ua_both))

    print()
    print("Summary:")

    op_rp = (None, None)
    ua_both = (None, None)

    if len(time_op_rp) > 2:
        op_rp = (statistics.mean(time_op_rp), statistics.stdev(time_op_rp))
        print("RP-OP -> Mean: %f, stdev: %f" % op_rp)
        
    if len(time_ua_both) > 2:
        ua_both = (statistics.mean(time_ua_both), statistics.stdev(time_ua_both))
        print("UA-RP and UA-OP -> Mean: %f, stdev: %f" % ua_both)
        
    return time_ua_both, time_op_rp

print("""  ________   _____    __  __                __     __          __           ___                __                     
/_  __/ /  / ___/   / / / /___ _____  ____/ /____/ /_  ____ _/ /_____     /   |  ____  ____ _/ /_  ______  ___  _____
/ / / /   \__ \   / /_/ / __ `/ __ \/ __  / ___/ __ \/ __ `/ //_/ _ \   / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
/ / / /______/ /  / __  / /_/ / / / / /_/ (__  ) / / / /_/ / ,< /  __/  / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/_/ /_____/____/  /_/ /_/\__,_/_/ /_/\__,_/____/_/ /_/\__,_/_/|_|\___/  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                                                         /____/                   
""")

parser = argparse.ArgumentParser(description='PCAP Pyshark reader')
parser.add_argument('--folder', metavar='<folder with results>', help='folder with results', required=False)
parser.add_argument('--pcap', metavar='<pcap capture file>', help='pcap file to parse', required=False)
parser.add_argument('--tlskey', metavar='<tls key log file>', help='key log file to decrypt tls messages', required=False)

args = parser.parse_args()

if args.folder:
    algs = ['rsa', 'ecdsa', 'dilithium2', 'dilithium3', 'dilithium5', 'falcon512', 'falcon1024']

    if not os.path.isdir(args.folder):
        print('"{}" does not exist.'.format(args.folder), file=sys.stderr)
        exit(-1)
        
    if not os.path.isdir(args.folder + '/tcpdump'):
        print('folder tcpdump not found in "{}".'.format(args.folder), file=sys.stderr)
        exit(-1)
        
    if not os.path.isdir(args.folder + '/tls_debug'):
        print('folder tls_debug not found in "{}".'.format(args.folder), file=sys.stderr)
        exit(-1)
        
    results = {}
    
    if os.path.isfile(f'{args.folder}/tls_handshake_times.csv'):
        print(f"{args.folder}/tls_handshake_times.csv already exists, exiting")
        exit()
        
    for file in os.listdir(args.folder + "/tcpdump"):
        if file.endswith(".pcap") and file != ".pcap":
            found = ''
        
            #handle different names in the .pcap file            
            for alg in algs:
                if alg in file:
                    found = alg
                    break
                
            if not found:
                continue
                
            pcap = glob.glob(f'{args.folder}/tcpdump/*{found}*.pcap')
            keylog = glob.glob(f'{args.folder}/tls_debug/*{found}*')
            
            if not pcap or not keylog:
                print(f"Can't find pcap ('{args.folder}/tcpdump/*{found}*.pcap) or keylog ({args.folder}/tls_debug/*{found}*) for {found}")
                continue
                
            cap = pyshark.FileCapture(pcap[0], display_filter="tls", override_prefs={'tls.keylog_file': keylog[0]}, use_json=True)
            
            results[found] = exec(cap, found)
            
    with open(f'{args.folder}/tls_handshake_times.csv', 'w+') as myfile:
        wr = csv.writer(myfile)
        
        results_list = []
        
        for alg in algs:
            if alg in results:
                results_list.append(results[alg][0])
                results_list.append(results[alg][1])
        
        wr.writerows(itertools.zip_longest(*results_list))
        
            
if not args.folder:
    if not os.path.isfile(args.pcap):
        print('"{}" does not exist.'.format(args.pcap), file=sys.stderr)
        exit(-1)
        
    if args.tlskey is not None:
        cap = pyshark.FileCapture(args.pcap, display_filter="tls", override_prefs={'tls.keylog_file': args.tlskey}, use_json=True)
    else:
        cap = pyshark.FileCapture(args.pcap, display_filter="tls", use_json=True)
        
    exec(cap, 'unknown')
