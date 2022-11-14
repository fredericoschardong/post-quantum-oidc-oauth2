#!/usr/bin/gnuplot -c

#
# usage: ./plot-boxplot.sh
# it saves a file named results.png into each folder with experiment results
#

reset

algs = "rsa ecdsa dilithium2 dilithium3 dilithium5 falcon512 falcon1024 sphincsshake256128fsimple sphincsshake256192fsimple sphincsshake256256fsimple"
plots = "reqs time"

file_exists(file) = system("[ -f ".file." ] && echo '1' || echo '0'") + 0

do for [op_rp in system("ls -d --quoting-style=c */")]{
    do for [test in system(sprintf("ls -d --quoting-style=c %s/*/", op_rp))]{
        do for [p in plots]{
            reset
            
            col="$1"
            
            if (p eq 'reqs'){
                col="$2"
            }
            
            set terminal png size 1400,300;
            set output sprintf('%s/results_%s.png', test, p)

            set style fill solid 0.25 border -1
            set style boxplot outliers pointtype 1
            set style data boxplot
            set pointsize 0.5

            set xtics ("RSA" 1, "ECDSA" 2, "Dilithium 2" 3, "Dilithium 3" 4, "Dilithium 5" 5, "Falcon 512" 6, "Falcon 1024" 7, "SPHINCS+128f" 8, "SPHINCS-192f" 9, "SPHINCS+256f" 10)

            system(sprintf("rm -f %s*.csv", p))

            i = 0

            #FIXME catch missing folders/algorithms
            do for [alg in algs]{
                f = system(sprintf("ls -d --quoting-style=c %s/logs/detailed/*TLS=%s*JWT=%s* 2>/dev/null", test, alg, alg))
                
                #print f
                #print strlen(f)
                #print file_exists(f) 
                
                if ( strlen(f) && file_exists(f) ){
                    system(sprintf("sed -e 's/\"//g' %s | sed '1d' | awk -F ',' '{print %s}' >> %s_%d.csv", f, col, p, i))
                    i = i + 1
                }
            }

            if ( i > 1 ){
                set datafile separator ","

                plot for [j=1:i] sprintf('<paste -d "," %s_*.csv', p) u (j):j notitle

                system(sprintf("rm -f %s*.csv", p))
            }
        }
    }
}

system("rm -f *.csv")
