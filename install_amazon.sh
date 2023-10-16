#!/bin/bash
# Author: Frederico Schardong
# This script prepares two amazon machines to act as OP and RP, they must be ubuntu x86 instances
if [ -z "${OP_IP}" ]; then
    echo "please, set the \$OP_IP env variable with the IPv4 address of the OIDC Provider (OP) before calling this script"
fi

if [ -z "${RP_IP}" ]; then
    echo "please, set the \$RP_IP env variable with the IPv4 address of the OIDC Relying Party (RP) before calling this script"
fi

if [ -z "${AMAZON_PEM_FILE}" ]; then
    echo "please, set the \$AMAZON_PEM_FILE env variable pointing to the localtion of the .pem file downloaded from Amazon EC2 to SSH into the machines"
    exit
fi

if [ -z "${AMAZON_USER}" ]; then
    echo "\$AMAZON_USER was not set... assuming ubuntu"
    AMAZON_USER="ubuntu"
fi

# on local, prepares the stage (source code to scp into the ec2 machines)
rm -Rf op_certs* rp_certs* code.tar.gz
find . -name "*.pyc" -exec rm -f {} \; > /dev/null 2>&1
tar -zcvf code.tar.gz *.yml op rp user_agent > /dev/null 2>&1

scp -i $AMAZON_PEM_FILE code.tar.gz $AMAZON_USER@$OP_IP:~/
(($? != 0)) && { echo "Command 'scp -i $AMAZON_PEM_FILE code.tar.gz $AMAZON_USER@$OP_IP:~/' exited with non-zero"; exit 1; }

scp -i $AMAZON_PEM_FILE code.tar.gz $AMAZON_USER@$RP_IP:~/
(($? != 0)) && { echo "Command 'scp -i $AMAZON_PEM_FILE code.tar.gz $AMAZON_USER@$RP_IP:~/' exited with non-zero"; exit 1; }

rm code.tar.gz

# on both OP and RP install docker and docker-compose
declare -a IPs=("$RP_IP" "$OP_IP")

for index in "${!IPs[@]}"; do
IP=${IPs[$index]}

echo ""
echo ""
echo "installing docker on $IP"
echo ""
echo ""

ssh $AMAZON_USER@$IP -i $AMAZON_PEM_FILE << EOF
    rm -Rf op* rp* user_agent results
    command -v docker && echo "Docker already installed" && exit
    sudo apt-get update
    sudo apt-get remove docker docker-engine docker.io containerd runc
    sudo apt-get install -y ca-certificates curl gnupg lsb-release
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    sudo groupadd docker
    sudo usermod -aG docker $AMAZON_USER
    newgrp docker 
EOF
done

# on OP
ssh $AMAZON_USER@$OP_IP -i $AMAZON_PEM_FILE << EOF
    rm -Rf op* rp* user_agent results
    tar -xvzf code.tar.gz 
    docker system prune -a --volumes -f
    SUBJECT_ALT_NAME_TYPE=IP OP_IP=$OP_IP docker-compose -f docker-compose-amazon.yml build op
    docker create -ti --name dummy ${AMAZON_USER}_op bash
    rm -Rf op_certs
    docker cp dummy:/op_certs ~/op_certs
    docker rm -f dummy
    tar -zcvf op_certs.tar.gz op_certs
EOF

# on local
rm -Rf op_certs*

scp -r -i $AMAZON_PEM_FILE $AMAZON_USER@$OP_IP:~/op_certs.tar.gz .
(($? != 0)) && { echo "Command 'scp -r -i $AMAZON_PEM_FILE $AMAZON_USER@$OP_IP:~/op_certs.tar.gz .' exited with non-zero"; exit 1; }

scp -r -i $AMAZON_PEM_FILE op_certs.tar.gz $AMAZON_USER@$RP_IP:~/op_certs.tar.gz
(($? != 0)) && { echo "Command 'scp -r -i $AMAZON_PEM_FILE op_certs.tar.gz $AMAZON_USER@$RP_IP:~/op_certs.tar.gz' exited with non-zero"; exit 1; }

tar -xvzf op_certs.tar.gz 

#on OP
ssh $AMAZON_USER@$OP_IP -i $AMAZON_PEM_FILE << EOF
    OP_IP=$OP_IP RP_IP=$RP_IP TLS_SIGN=rsa JWT_SIGN=rsa LOG_LEVEL=DEBUG docker-compose -f docker-compose-amazon.yml up -d op
EOF

# on RP
ssh $AMAZON_USER@$RP_IP -i $AMAZON_PEM_FILE << EOF
    tar -xvzf code.tar.gz 
    docker system prune -a --volumes -f
    SUBJECT_ALT_NAME_TYPE=IP RP_IP=$RP_IP docker-compose -f docker-compose-amazon.yml build rp
    docker create -ti --name dummy ${AMAZON_USER}_rp bash
    rm -Rf rp_certs
    docker cp dummy:/rp_certs ~/rp_certs
    docker rm -f dummy
    tar -zcvf rp_certs.tar.gz rp_certs
    tar -xvzf op_certs.tar.gz 
    OP_IP=$OP_IP RP_IP=$RP_IP TLS_SIGN=rsa JWT_SIGN=rsa LOG_LEVEL=DEBUG docker-compose -f docker-compose-amazon.yml up -d rp
EOF

# on local
rm -Rf rp_certs*

scp -i $AMAZON_PEM_FILE $AMAZON_USER@$RP_IP:~/rp_certs.tar.gz .
(($? != 0)) && { echo "Command 'scp -i $AMAZON_PEM_FILE $AMAZON_USER@$RP_IP:~/rp_certs.tar.gz .' exited with non-zero"; exit 1; }

tar -xvzf rp_certs.tar.gz 

docker stop $(docker ps -a -q)
docker container rm $(docker container ls -a -q) && docker volume rm post_quantum_op_certs post_quantum_rp_certs
docker rmi $(docker images -a --filter=dangling=true -q)
docker-compose -f docker-compose-amazon.yml build user_agent user_agent-tcpdump
docker system prune -a --volumes -f

echo "Testing if everything is working...."
OP_IP=$OP_IP RP_IP=$RP_IP LOG_LEVEL=DEBUG TLS_SIGN=rsa JWT_SIGN=rsa REPEAT=1 docker-compose -f docker-compose-amazon.yml up --exit-code-from user_agent user_agent user_agent-tcpdump

if [ $? -eq 0 ]; then
    echo -e "\n\n\n"
    echo "Apparently everything is working! You can now run the realistic tests with:"
    echo "OP_IP=$OP_IP RP_IP=$RP_IP AMAZON_USER=$AMAZON_USER AMAZON_PEM_FILE=$AMAZON_PEM_FILE LOG_LEVEL=DEBUG ./run_experiments.sh &"
else
    echo "Something went wrong!"
fi
