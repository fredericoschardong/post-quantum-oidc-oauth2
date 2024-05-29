import os
import csv
import sys

algs = ["rsa", "ecdsa", "dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024", "sphincsshake256128fsimple", "sphincsshake256192fsimple", "sphincsshake256256fsimple"]

for alg in algs:
    filename = alg + '.csv'
    
    if os.path.exists(filename):
        os.remove(filename)

ratios = []

for i, argv in enumerate(sys.argv[1:]):
    ratios.append([i])

    with open(argv) as csvfile:
        reader = csv.reader(csvfile, delimiter=' ')

        for index, line in enumerate(reader):
            with open(algs[index] + '.csv', 'a+') as writer:
                wr = csv.writer(writer, delimiter=' ')
                wr.writerow(line)
                
                ratios[-1].append(float(line[3]) / float(line[1]))
                
with open('ratios.csv', 'w+') as writer:
    wr = csv.writer(writer, delimiter=' ')
    wr.writerows(ratios)
