#!/bin/bash
# Author: Frederico Schardong

if ! command -v mergecap &> /dev/null
then
    echo "mergecap could not be found, please install"
    exit
fi

if ! command -v gnuplot &> /dev/null
then
    echo "gnuplot could not be found, please install"
    exit
fi

if ! command -v docker &> /dev/null
then
    echo "docker could not be found, please install"
    exit
fi

if ! command -v docker-compose &> /dev/null
then
    echo "docker-compose could not be found, please install"
    exit
fi

if [ -z "${OP_IP}" ]; then
    echo "\$OP_IP was not set... assuming op (i.e. the hostname in docker-compose)"
    OP_IP="op"
fi

if [ -z "${RP_IP}" ]; then
    echo "\$RP_IP was not set... assuming rp (i.e. the hostname in docker-compose)"
    RP_IP="rp"
fi

if [ -z "${SAVE_TLS_DEBUG}" ]; then
    echo "\$SAVE_TLS_DEBUG was not set... assuming True)"
    SAVE_TLS_DEBUG="True"
fi

if [ -z "${TIMEOUT}" ]; then
    TIMEOUT=10000
fi

echo "Warning: you must call this script from python/post_quantum/ as it uses relative path for some operations!"

if [ "$OP_IP" != "op" ]; then
    if ! command -v traceroute &> /dev/null
    then
        echo "traceroute could not be found, please install"
        exit
    fi
    
    if [ -z "${AMAZON_PEM_FILE}" ]; then
        echo "please, set the \$AMAZON_PEM_FILE env variable pointing to the localtion of the .pem file downloaded from Amazon EC2 to SSH into the machines"
        exit
    fi

    if [ -z "${AMAZON_USER}" ]; then
        echo "\$AMAZON_USER was not set... assuming ubuntu"
        AMAZON_USER="ubuntu"
    fi
fi

if [ -z "${REPEAT}" ]; then
    echo "\$REPEAT was not set... assuming 1000"
    REPEAT="1000"
fi

if [ -z "${TEST}" ]; then
    echo "\$TEST was not set... assuming all"
    TEST="all"
fi

#all or same (i.e. same algorithm for JWT and TLS)
if [ -z "${SCOPE}" ]; then 
    echo "\$SCOPE was not set... assuming same"
    SCOPE="same"
fi

if [ -z "${LOG_LEVEL}" ]; then 
    echo "\$LOG_LEVEL was not set... assuming CRITICAL"
    LOG_LEVEL="CRITICAL"
fi


date=$(date '+%Y-%m-%d-%H-%M-%S')
RESULTS_FOLDER="results/$OP_IP-$RP_IP/$TEST-$REPEAT-$date/"

mkdir -p $RESULTS_FOLDER

rm -Rf user_agent/tcpdump/*.pcap
rm -Rf user_agent/app/logs/detailed/*.csv
rm -Rf user_agent/app/logs/*.csv
rm -Rf user_agent/app/tls_debug/user_agent.tls_debug

CAPTION_all="in our realistic evaluation scenario"
CAPTION_token="for the \\\textbf{token} request"

caption=CAPTION_$TEST
caption=${!caption}

resumed_results="user_agent/app/logs/resumed_TEST=$TEST.csv"

declare -A mean_results
declare -A stdev_results

declare -a TLS=("rsa" "ecdsa" "dilithium2" "dilithium3" "dilithium5" "falcon512" "falcon1024" "sphincsshake256128fsimple" "sphincsshake256192fsimple" "sphincsshake256256fsimple")
declare -a JWT=("rsa" "ecdsa" "dilithium2" "dilithium3" "dilithium5" "falcon512" "falcon1024" "sphincsshake256128fsimple" "sphincsshake256192fsimple" "sphincsshake256256fsimple")
declare -a TLS_PRETTY_NAMEs=("RSA" "ECDSA" "Dilithium 2" "Dilithium 3" "Dilithium 5" "Falcon-512" "Falcon-1024" "SPHINCS+-SHAKE256-128f-simple" "SPHINCS+-SHAKE256-192f-simple" "SPHINCS+-SHAKE256-256f-simple")

if [ "$SCOPE" = "all" ]; then
    echo "Generating all possible combinations between TLS and JWT signing algorithms for TEST=$TEST with $REPEAT repetitions using OP_IP=$OP_IP and RP_IP=$RP_IP"
fi

if [ "$OP_IP" = "op" ]; then
    docker kill $(docker ps -a -q) > /dev/null 2>&1
    docker stop $(docker ps -a -q) > /dev/null 2>&1
    docker rm $(docker ps -a -q) > /dev/null 2>&1
fi

_term() { 
    echo ""
    echo "Copying files..."
    
    if [ "$OP_IP" != "op" ]; then
        traceroute_op=$(mktemp)
        traceroute_rp=$(mktemp)
        
        traceroute -4 $OP_IP >> $traceroute_op &
        traceroute -4 $RP_IP >> $traceroute_rp &
    fi

    if [ "$SAVE_TLS_DEBUG" = "True" ]; then
        if [ "$OP_IP" != "op" ]; then
            scp -i $AMAZON_PEM_FILE $AMAZON_USER@$OP_IP:~/op/tcpdump/*.pcap op/tcpdump/
            scp -i $AMAZON_PEM_FILE $AMAZON_USER@$OP_IP:~/op/app/tls_debug/*.tls_debug op/app/tls_debug/
        fi
            
        echo "We need superuser permission to define $USER:$USER ownership of the downloaded OP files"
        sudo chown -Rf $USER:$USER op/tcpdump/* op/app/tls_debug/* user_agent/tcpdump/* user_agent/app/tls_debug/*
        
        echo "Running mergecap"
        
        for filepath in op/tcpdump/*.pcap; do
            filename=$(basename $filepath)
            mergecap $filepath user_agent/tcpdump/$filename -w user_agent/tcpdump/user_agent_and_op_$filename
            mv user_agent/tcpdump/user_agent_and_op_$filename user_agent/tcpdump/$filename
        done

        for filepath in op/app/tls_debug/*.tls_debug; do
            filename=$(basename $filepath)
            cat $filepath user_agent/app/tls_debug/$filename >> user_agent/app/tls_debug/user_agent_and_op_$filename
            mv user_agent/app/tls_debug/user_agent_and_op_$filename user_agent/app/tls_debug/$filename
            cat $filepath user_agent/app/tls_debug/$filename >> user_agent/app/tls_debug/all.tls_debug
        done
    fi

    if [ "$OP_IP" != "op" ]; then
        echo "Running traceroute"
        
        wait $(jobs -p)
        
        echo "Traceroute from user_agent to $OP_IP (our OIDC)" >> $RESULTS_FOLDER/traceroute_user_agent_to_op
        cat $traceroute_op >> $RESULTS_FOLDER/traceroute_user_agent_to_op

        echo "Traceroute from user_agent to $RP_IP (our RP)" >> $RESULTS_FOLDER/traceroute_user_agent_to_rp
        cat $traceroute_rp >> $RESULTS_FOLDER/traceroute_user_agent_to_rp
        
        echo "Done!"
    fi
    
    mv user_agent/tcpdump $RESULTS_FOLDER/
    mv user_agent/app/logs $RESULTS_FOLDER/
    mv user_agent/app/tls_debug $RESULTS_FOLDER/
    
    mkdir user_agent/tcpdump user_agent/app/logs user_agent/app/logs/detailed user_agent/app/tls_debug
    
    echo ""
    echo "GNUPLOTing new results"
    cd results
    chmod +x plot-boxplot.sh
    ./plot-boxplot.sh
    cd ..
    
    exit
}

trap _term SIGTERM
trap _term SIGKILL
trap _term SIGINT

if [ "$OP_IP" != "op" ]; then
    ssh $AMAZON_USER@$OP_IP -i $AMAZON_PEM_FILE "rm -Rf op/tcpdump/*.pcap op/app/tls_debug/*.tls_debug"
fi

rm -Rf op/tcpdump/*.pcap user_agent/tcpdump/*.pcap op/app/tls_debug/*.tls_debug user_agent/app/tls_debug/*.tls_debug

if [ "$SAVE_TLS_DEBUG" = "True" ]; then
    op_services="op op-tcpdump"
    local_services="user_agent user_agent-tcpdump"
else
    op_services="op"
    local_services="user_agent"
fi

for tls_index in "${!TLS[@]}"; do
    tls=${TLS[$tls_index]}
    
    if [ "$OP_IP" != "op" ]; then
        ssh $AMAZON_USER@$OP_IP -i $AMAZON_PEM_FILE "docker container stop $(docker container ls -a -q) || docker container rm $(docker container ls -a -q) || docker volume rm post_quantum_op_certs post_quantum_rp_certs || docker rmi $(docker images -a --filter=dangling=true -q) || TIMEOUT=$TIMEOUT OP_IP=$OP_IP RP_IP=$RP_IP TLS_SIGN=$tls JWT_SIGN=$tls LOG_LEVEL=$LOG_LEVEL SAVE_TLS_DEBUG=$SAVE_TLS_DEBUG docker-compose -f docker-compose-amazon.yml up --force-recreate -d $op_services" >> $RESULTS_FOLDER/log_OP 2>&1
        ssh $AMAZON_USER@$RP_IP -i $AMAZON_PEM_FILE "docker container stop $(docker container ls -a -q) || docker container rm $(docker container ls -a -q) || docker volume rm post_quantum_op_certs post_quantum_rp_certs || docker rmi $(docker images -a --filter=dangling=true -q) || TIMEOUT=$TIMEOUT OP_IP=$OP_IP RP_IP=$RP_IP TLS_SIGN=$tls JWT_SIGN=$tls LOG_LEVEL=$LOG_LEVEL docker-compose -f docker-compose-amazon.yml up --force-recreate -d rp" >> $RESULTS_FOLDER/log_RP 2>&1
    fi

    for jwt_index in "${!JWT[@]}"; do
        jwt=${JWT[$jwt_index]}
        
        if [ "$SCOPE" = "same" ] && [ "${tls}" != "${jwt}" ]; then
            continue
        fi
    
        # SECONDS is a special feature of bash
        SECONDS=0
        
        if [ "$OP_IP" = "op" ]; then
            TIMEOUT=$TIMEOUT LOG_LEVEL=$LOG_LEVEL OP_IP=$OP_IP RP_IP=$RP_IP TLS_SIGN=$tls JWT_SIGN=$jwt REPEAT=$REPEAT SAVE_TLS_DEBUG=$SAVE_TLS_DEBUG TEST=$TEST docker-compose up --force-recreate --exit-code-from user_agent $local_services op rp op-tcpdump >> $RESULTS_FOLDER/log_user_agent 2>&1
        else
            TIMEOUT=$TIMEOUT LOG_LEVEL=$LOG_LEVEL OP_IP=$OP_IP RP_IP=$RP_IP TLS_SIGN=$tls JWT_SIGN=$jwt REPEAT=$REPEAT SAVE_TLS_DEBUG=$SAVE_TLS_DEBUG TEST=$TEST docker-compose -f docker-compose-amazon.yml up --force-recreate --exit-code-from user_agent $local_services >> $RESULTS_FOLDER/log_user_agent 2>&1
        fi
        
        IFS=, read -r a b c d e f g mean_req_sec stdev_req_sec extra < <(tail -n1 $resumed_results)
        
        duration=$SECONDS
        
        echo "Generating TLS: $tls, JWT: $jwt -> $mean_req_sec $stdev_req_sec (total time: $(($duration / 60)):$(($duration % 60)))"
        
        mean_results[$tls_index,$jwt_index]=`awk -v a="$mean_req_sec" 'BEGIN{printf("%.2f\n", a)}'`
        stdev_results[$tls_index,$jwt_index]=`awk -v a="$stdev_req_sec" 'BEGIN{printf("%.2f\n", a)}'`
    done
done

_term
