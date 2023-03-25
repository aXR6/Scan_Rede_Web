#!/bin/bash

echo -e "\033[1;31m--------------------- PREPARANDO O AMBIENTE --------------------- \033[0m \033[1;31m \033[0m"
apt update && apt -y install net-tools
apt -y install apt-transport-https ca-certificates curl gnupg2 software-properties-common
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list
echo -e "\033[1;31m--------------------- PREPARANDO O AMBIENTE --------------------- \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m--------------------- INSTALANDO O DOCKER --------------------- \033[0m \033[1;31m \033[0m"
apt-get update
apt-get -y install docker-ce docker-ce-cli containerd.io
docker -version
echo -e "\033[1;31m--------------------- INSTALANDO O DOCKER --------------------- \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m--------------------- INSTALANDO O PORTAINER --------------------- \033[0m \033[1;31m \033[0m"
docker volume create portainer_data
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:latest
echo -e "\033[1;31m--------------------- INSTALANDO O PORTAINER --------------------- \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m--------------------- FORMA DE ACESSAR --------------------- \033[0m \033[1;31m \033[0m"
ip_address=$(ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}')
echo -e "\033[1;31m [ Acessando o Portainer: https://$ip_address:9443 ] \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m [ Primeiro Acesso ] \033[0m \033[1;31m \033[0m"
echo -e "\033[1;31m [ https://docs.portainer.io/start/install/server/setup ] \033[0m \033[1;31m \033[0m"
echo -e "\033[1;31m--------------------- FORMA DE ACESSAR --------------------- \033[0m \033[1;31m \033[0m"