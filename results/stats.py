import csv
import sys
import statistics

algs = ["rsa", "ecdsa", "dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024", "sphincsshake256128fsimple", "sphincsshake256192fsimple", "sphincsshake256256fsimple"]

if len(sys.argv) < 4:
    print("OIDC csv, TLS csv and algo, constant")
    exit(-1)

with open(sys.argv[1]) as csvfile:
    reader = csv.reader(csvfile, delimiter=',', quotechar='"')
    
    #ignore header
    next(reader)
    
    data = [float(line[0]) for line in reader if float(line[0]) < 100]

tls_ua_data = []
tls_op_rp_data = []

with open(sys.argv[2]) as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    index = algs.index(sys.argv[3])
    index = index * 2
    
    for line in reader:
        if line[index] != '':# and float(line[index]) < 1000:
            tls_ua_data.append((float(line[index]) / 1000)) # divide by 1000 to get time in seconds
        
        if line[index + 1] != '': # add time between OP-RP
            tls_op_rp_data.append((float(line[index + 1]) / 1000)) 

print(sys.argv[4], 
      statistics.mean(data), 
      statistics.stdev(data), 
      
      #17 requests between user agent and RP or OP
      17*statistics.mean(tls_ua_data) +
       
      #5 requests between RP and OP
      5*(statistics.mean(tls_op_rp_data) if len(tls_op_rp_data) > 2 else 0),

      17*statistics.stdev(tls_ua_data) + 5*(statistics.stdev(tls_op_rp_data) if len(tls_op_rp_data) > 2 else 0)
)
