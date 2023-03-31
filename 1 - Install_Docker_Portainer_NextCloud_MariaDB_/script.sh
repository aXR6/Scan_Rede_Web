#!/bin/bash

echo -e "\033[1;31m--------------------- PREPARANDO O AMBIENTE --------------------- \033[0m \033[1;31m \033[0m"
# Atualiza o sistema operacional
apt-get update && apt-get upgrade -y

# Instala os pacotes necessários
apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common

# Adiciona a chave GPG oficial do Docker
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -

# Adiciona o repositório oficial do Docker
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"

# Atualiza novamente os pacotes
apt-get update

# Instala o Docker CE, Docker CE CLI e o Containerd.io
apt-get install -y docker-ce docker-ce-cli containerd.io

# Adiciona o usuário atual ao grupo do Docker
usermod -aG docker $USER

# Configura o Portainer CE
docker volume create portainer_data
docker run -d -p 9000:9000 --name portainer --restart always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce

# Imprimir instruções finais
echo ""
echo "Docker e Portainer foram instalados com sucesso!"
echo "Para usar o Docker sem precisar usar sudo, faça logout e login novamente."
echo "Acesse o Portainer em http://localhost:9000."
echo -e "\033[1;31m--------------------- PREPARANDO O AMBIENTE --------------------- \033[0m \033[1;31m \033[0m"