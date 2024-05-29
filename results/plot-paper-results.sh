#!/usr/bin/gnuplot -c

algs = "rsa ecdsa dilithium2 dilithium3 dilithium5 falcon512 falcon1024 sphincsshake256128fsimple sphincsshake256192fsimple sphincsshake256256fsimple"
file_exists(file) = system("[ -f ".file." ] && echo '1' || echo '0'") + 0

reset

#set terminal png size 800,250;
set terminal pdfcairo enhanced color dashed font "Alegreya, 10" rounded size 16 cm, 6 cm

set style fill solid 0.25 border -1
set style histogram rowstacked
set style data histograms
set boxwidth 0.75 relative
set ylabel "Seconds"

#set key opaque title
#set key left top

unset key

set grid ytics
set style line 12 lc rgb '#808080' lt 0 lw 1
set grid back ls 12

set xtics ("RSA" 0, "ECDSA" 1, "DL 2" 2, "DL 3" 3, "DL 5" 4, "FN 512" 5, "FN 1024" 6, "SPH+128" 7, "SPH+192" 8, "SPH+256" 9)

set xrange [-0.5:9.5]

scenarios = 1

do for [op_rp in system("ls -d --quoting-style=c */")]{
  do for [test in system(sprintf("ls -d --quoting-style=c %s/*/", op_rp))]{
    set output sprintf('%s/stacked.pdf', test, p)

    system(sprintf('rm -Rf %s/results.csv', test, p))

    i = 1

    do for [alg in algs]{
        f = system(sprintf("ls -d --quoting-style=c %s/logs/detailed/*TLS=%s*JWT=%s* 2>/dev/null", test, alg, alg))
        
        if ( strlen(f) && file_exists(f) ){
            system(sprintf("python3 stats.py %s %s/tls_handshake_times.csv %s %d >> %s/results.csv", f, test, alg, i, test))
            i = i + 1
        }
    }

    scale = 'column(2)/(column(2)+column(4))'

    if ( i > 1){
        plot sprintf('%s/results.csv', test) u ($4) t "TLS", \
            sprintf('%s/results.csv', test) u ($2-$4) t "Total", \
            sprintf('%s/results.csv', test) u 0:2:3 with errorbars notitle lw 2 lt -1, \
            sprintf('%s/results.csv', test) u 0:4:5 with errorbars notitle lw 2 lt -1
    }
  }

  scenarios = scenarios + 1
}

set output "stacked.pdf"
unset yrange

reset

set terminal pdfcairo enhanced color dashed font "Alegreya, 12" rounded size 16 cm, 8 cm

set grid ytics
set border 3 back 
set tics nomirror
set style line 12 lc rgb '#808080' lt 0 lw 1
set grid back ls 12

#TODO find a way to automate this
set xtics ("30ms" 0, "140ms" 1, "225ms" 2, "320ms" 3, "" 4, "30ms" 5, "140ms" 6, "225ms" 7, "320ms" 8, "" 9, "30ms" 10, "140ms" 11, "225ms" 12, "320ms" 13, "" 14, "30ms" 15, "140ms" 16, "225ms" 17, "320ms" 18, "" 19, "30ms" 20, "140ms" 21, "225ms" 22, "320ms" 23, "" 24, "30ms" 25, "140ms" 26, "225ms" 27, "320ms" 28, "" 29, "30ms" 30, "140ms" 31, "225ms" 32, "320ms" 33, "" 34, "30ms" 35, "140ms" 36, "225ms" 37, "320ms" 38, "" 39, "30ms" 40, "140ms" 41, "225ms" 42, "320ms" 43, "" 44, "30ms" 45, "140ms" 46, "225ms" 47, "320ms" 48,)

set style data histogram 
set style histogram rowstack gap 1 title offset 0,-1
set style fill solid border -1
set boxwidth 0.8 relative

set bmargin at screen 0.19
set tmargin at screen 0.98
set lmargin at screen 0.075
set rmargin at screen 1

#set key opaque title
set key left top
set key invert

# scenarios=5 #scenarios + 1 actually

set ylabel "Seconds"

set xrange[-1:scenarios*10-1]

#unset xtics
set xtics rotate by 60 right

#set key noautotitle

system("rm -Rf *.csv")
system("python3 prepare-plot-all.py $(ls -1v */*/results.csv)")

plot newhistogram "RSA", \
       'rsa.csv' u ($4) title "TLS" linecolor rgb "red", \
       ''        u ($2-$4) title "OIDC" linecolor rgb "green" , \
       ''        u (column(0)+scenarios*0):2:3 with errorbars notitle lw 2 lt -1, \
       ''        u (column(0)+scenarios*0):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "ECDSA", \
       'ecdsa.csv' u ($4) title "" linecolor rgb "red", \
       ''          u ($2-$4) title "" linecolor rgb "green" , \
       ''          u (column(0)+scenarios*1):2:3 with errorbars notitle lw 2 lt -1, \
       ''          u (column(0)+scenarios*1):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "DL 2", \
       'dilithium2.csv' u ($4) title "" linecolor rgb "red", \
       ''               u ($2-$4) title "" linecolor rgb "green" , \
       ''               u (column(0)+scenarios*2):2:3 with errorbars notitle lw 2 lt -1, \
       ''               u (column(0)+scenarios*2):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "DL 3", \
       'dilithium3.csv' u ($4) title "" linecolor rgb "red", \
       ''               u ($2-$4) title "" linecolor rgb "green" , \
       ''               u (column(0)+scenarios*3):2:3 with errorbars notitle lw 2 lt -1, \
       ''               u (column(0)+scenarios*3):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "DL 5", \
       'dilithium5.csv' u ($4) title "" linecolor rgb "red", \
       ''               u ($2-$4) title "" linecolor rgb "green" , \
       ''               u (column(0)+scenarios*4):2:3 with errorbars notitle lw 2 lt -1, \
       ''               u (column(0)+scenarios*4):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "FN 512", \
       'falcon512.csv' u ($4) title "" linecolor rgb "red", \
       ''              u ($2-$4) title "" linecolor rgb "green", \
       ''              u (column(0)+scenarios*5):2:3 with errorbars notitle lw 2 lt -1, \
       ''              u (column(0)+scenarios*5):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "FN 1024", \
       'falcon1024.csv' u ($4) title "" linecolor rgb "red", \
       ''               u ($2-$4) title "" linecolor rgb "green", \
       ''               u (column(0)+scenarios*6):2:3 with errorbars notitle lw 2 lt -1, \
       ''               u (column(0)+scenarios*6):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "SP+128", \
       'sphincsshake256128fsimple.csv' u ($4) title "" linecolor rgb "red", \
       ''               u ($2-$4) title "" linecolor rgb "green", \
       ''               u (column(0)+scenarios*7):2:3 with errorbars notitle lw 2 lt -1, \
       ''               u (column(0)+scenarios*7):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "SP+192", \
       'sphincsshake256192fsimple.csv' u ($4) title "" linecolor rgb "red", \
       ''               u ($2-$4) title "" linecolor rgb "green", \
       ''               u (column(0)+scenarios*8):2:3 with errorbars notitle lw 2 lt -1, \
       ''               u (column(0)+scenarios*8):4:5 with errorbars notitle lw 2 lt -1, \
     newhistogram "SP+256", \
       'sphincsshake256256fsimple.csv' u ($4) title "" linecolor rgb "red", \
       ''               u ($2-$4) title "" linecolor rgb "green", \
       ''               u (column(0)+scenarios*9):2:3 with errorbars notitle lw 2 lt -1, \
       ''               u (column(0)+scenarios*9):4:5 with errorbars notitle lw 2 lt -1, \

reset

set terminal pdfcairo enhanced color dashed font "Alegreya, 13" rounded size 16 cm, 5 cm

set output 'ratios.pdf'

#set grid ytics
#set style line 12 lc rgb '#808080' lt 0 lw 1
#set grid back ls 12

set xtics ("30ms" 0, "140ms" 1, "225ms" 2, "320ms" 3)

set style line 11 lc rgb '#808080' lt 1
set border 3 back #ls 11
set tics nomirror

set style line 12 lc rgb '#808080' lt 0 lw 1
set grid back ls 12

set key bottom right

set tmargin at screen 0.95
set bmargin at screen 0.1
set lmargin at screen 0.09
set rmargin at screen 0.96

set ylabel 'TLS Hand. Time / Total Time'
set xrange [-0.1:3.1]
set yrange [0:0.8]

set multiplot
set key at screen 0.30,0.11
plot 'ratios.csv' u 1:2 t 'RSA' w lp ls 1 ps 0.8, \
     ''           u 1:3 t 'ECDSA' w lp ls 2 ps 0.8

unset xtics;unset ytics
unset xlabel;unset ylabel
unset border

set key default opaque
set key bottom right
set key at screen 0.70,0.11
plot 'ratios.csv' u 1:4 t 'Dilithium 2' w lp ls 3 ps 0.8, \
     ''           u 1:5 t 'Dilithium 3' w lp ls 4 ps 0.8, \
     ''           u 1:6 t 'Dilithium 5' w lp ls 5 ps 0.8
     
unset xtics;unset ytics
unset xlabel;unset ylabel
unset border

set key default opaque
set key bottom right
set key at screen 0.50,0.11
plot 'ratios.csv' u 1:7 t 'Falcon 512' w lp ls 6 ps 0.8, \
     ''           u 1:8 t 'Falcon 1024' w lp ls 7 ps 0.8

unset xtics;unset ytics
unset xlabel;unset ylabel
unset border

set key default opaque
set key bottom right
set key at screen 0.93,0.11
plot 'ratios.csv' u 1:9 t 'SPHINCS+ 128' w lp ls 8 ps 0.8, \
     ''           u 1:10 t 'SPHINCS+ 192' w lp ls 9 ps 0.8, \
     ''           u 1:11 t 'SPHINCS+ 256' w lp ls 10 ps 0.8


unset multiplot
