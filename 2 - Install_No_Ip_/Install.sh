#!/bin/bash


echo -e "\033[1;31m[----------------------------------------------------------- VOCÊ PRECISARÁ -----------------------------------------------------------] \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[✔] Você precisará criar uma conta e um dominio antes. \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[----------------------------------------------------------- VOCÊ PRECISARÁ -----------------------------------------------------------] \033[0m \033[1;31m \033[0m"

apt update && apt install -y wget && cd /usr/local/src

echo -e "\033[1;31m[✔] Baixe o pacote de instalação mais recente do No-IP em https://www.noip.com/download. \033[0m \033[1;31m \033[0m"
echo -e "\033[1;31m[✔] Baixando.... \033[0m \033[1;31m \033[0m"
wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz

echo -e "\033[1;31m[✔] Abra o terminal Bash e navegue até o diretório onde o pacote de instalação foi baixado. \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[✔] Extraia o pacote usando o seguinte comando: \033[0m \033[1;31m \033[0m"
echo -e "\033[1;31m[✔] Extraindo.... \033[0m \033[1;31m \033[0m"
tar -xzvf noip-duc-linux.tar.gz

echo -e "\033[1;31m[✔] Acesse o diretório extraído: \033[0m \033[1;31m \033[0m"
echo -e "\033[1;31m[✔] Acessando a pasta.... \033[0m \033[1;31m \033[0m"
cd noip-2.1.9-1/

echo -e "\033[1;31m[✔] Compile o programa No-IP com o seguinte comando: \033[0m \033[1;31m \033[0m"
echo -e "\033[1;31m[✔] Compilando o software.... \033[0m \033[1;31m \033[0m"
sudo make

echo -e "\033[1;31m[----------------------------------------------------------- Observação -----------------------------------------------------------] \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[✔] O instalador do No-IP solicitará que você faça login na sua conta do No-IP. Digite suas credenciais de login para continuar. \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[✔] Depois de fazer login, o instalador do No-IP perguntará qual é o nome de host que você deseja atualizar automaticamente com o endereço IP do seu computador. Digite o nome de host desejado e pressione Enter. \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[✔] O instalador do No-IP solicitará que você configure as opções de atualização. Selecione as opções desejadas e siga as instruções na tela para concluir a configuração. \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[✔] Depois de concluir a configuração, o No-IP será iniciado automaticamente e começará a atualizar seu endereço IP no servidor No-IP. \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[----------------------------------------------------------- Observação -----------------------------------------------------------] \033[0m \033[1;31m \033[0m"

echo -e "\033[1;31m[✔] Instale o programa No-IP com o seguinte comando: \033[0m \033[1;31m \033[0m"
echo -e "\033[1;31m[✔] Instalando o software.... \033[0m \033[1;31m \033[0m"
sudo make install