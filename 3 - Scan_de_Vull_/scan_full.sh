#!/bin/bash

DirAtual=("${PWD}")
data=$(date +"%d_%m_%y_%A")
t=$(date +"%T")
#dir=("/home/$USER/Documentos/$data")
# Para Kali Linux
dir=("/home/$SUDO_USER/Documentos/$data")
mkdir $dir

##toolxmenu##
##################
##START toolxmenu##
toolxmenu() {
   CLEARMEN
   PS3=("└──> ToolXMenu : ")
   options=(
   	"(1º Faça)-Instalação dos comp/onentes"
   	"(2º Faça)-Instalação das ferramentas"
   	"Testar a Rede (Toda a REDE)"
   	"Testar Sites (Lista de SITES)"
   	"Baixar WordList Oficial Kali Linux"
   	"Informações sobre Hardware e SO"
   	"SAIR")
	    select opt in "${options[@]}"
	    do
	      case $opt in
		 "(1º Faça)-Instalação dos componentes")
		    INSTALLTOOLS
		    ;;
		 "(2º Faça)-Instalação das ferramentas")
		    INSTALLCOMP
		    ;;
		 "Testar a Rede (Toda a REDE)")
		    TOOLXREDE
		    ;;
		 "Testar Sites (Lista de SITES)")
		    TOOLXSITE
		    ;;
		 "Baixar WordList Oficial Kali Linux")
		    SECLIST
		    ;;
		 "Informações sobre Hardware e SO")
		    INFOMAQUINA
		    ;;
		 "SAIR")
		    exit 0
		    ;;
		 *) 
		    echo "A opção ($REPLY) não existe."
		    ;;
      esac
    done
}

##END toolxmenu##
################
##/toolxmenu##

##TOOLXSITE##
##################
##START TOOLXSITE##
TOOLXSITE() {
   CLEARMEN
   PS3=("└──> ToolXMenu : ")
   options=(
   	"(1º Faça)-Informe o Nome da lista (ex.: lst1.txt)"
   	"(2º Faça)-Informe o Diretorio da Lista (ex.: $DirAtual)"
   	"Testar a lista com o NIKTO"
   	"Testar a lista com o NMAP"
   	"Testar a lista com o GOBUSTER"
   	"Testar a lista com o Hydra"
   	"Testar a lista com o SSLYZE"
   	"Testar a lista com TODAS"
   	"SAIR")
   select opt in "${options[@]}"
   do
      case $opt in
         "(1º Faça)-Informe o Nome da lista (ex.: lst1.txt)")
            LSTFILE
            ;;
         "(2º Faça)-Informe o Diretorio da Lista (ex.: $DirAtual)")
            DIRFILE
            ;;
         "Testar a lista com o NIKTO")
            NIKTO
            ;;
         "Testar a lista com o NMAP")
            NMAP
            ;;
         "Testar a lista com o GOBUSTER")
            GOBUSTER
            ;;
         "Testar a lista com o Hydra")
            HYDRA
            ;;
         "Testar a lista com o SSLYZE")
            SSLYZE
            ;;
         "Testar a lista com TODAS")
            TODAS
            ;;
	 "SAIR")
	    break
            ;;
         *) echo "A opção ($REPLY) não existe.";;
      esac
     done
}
##END TOOLXSITE##
################
##/TOOLXSITE##

##TOOLXREDE##
##################
##START TOOLXREDE##
TOOLXREDE() {
   CLEARMEN
   PS3=("└──> ToolXMenu : ")
   options=(
   	"Onde nós estamos?"
   	"Verificar a rede"
      "Detectar serviços OnLine na rede"
   	"SAIR")
   select opt in "${options[@]}"
   do
      case $opt in
         "Onde nós estamos?")
            LOCALREDE
            ;;
         "Verificar a rede")
            SCANREDE
            ;;
         "Detectar serviços OnLine na rede")
            DETECTSERVICE
            ;;
	 "SAIR")
	    break
            ;;
         *) echo "A opção ($REPLY) não existe.";;
      esac
      done
}
##END TOOLXREDE##
################
##/TOOLXREDE##

DETECTSERVICE()
{
# Define a função que vai executar o comando nmap e detectar os serviços online
function detect_services {
    nmap -n -sP $1 | awk '/is up/ {print up}; {gsub (/\(|\)/,""); up = $NF}' | while read host; do
        nmap -n -sV $host | grep 'open' | awk '{print $1,$3,$4}' | while read service; do
            echo "$host: $service"
        done
    done
}

# Define a função que vai buscar os endereços de IP
function scan_network {
    for i in $(seq 1 254); do
        detect_services $1.$i &
    done
    wait
}

# Pede o endereço de IP inicial ao usuário
read -p "Digite o endereço de IP inicial: " ip_address

# Chama a função scan_network para iniciar a detecção de serviços online
scan_network $(echo $ip_address | cut -d '.' -f 1-3)
}

INFOMAQUINA()
{
echo -e "\033[1;31m:=> Informações do sistema: \033[0m"

echo -e "\033[1;31m:=> Informações do CPU \033[0m"
cat /proc/cpuinfo | grep "model name\|vendor_id\|cpu cores"

echo -e "\033[1;31m:=> Informações da memória \033[0m"
free -m

echo -e "\033[1;31m:=> Informações dos discos \033[0m"
df -h

echo -e "\033[1;31m:=> Informações dos dispositivos PCI \033[0m"
lspci

echo -e "\033[1;31m:=> Informações dos dispositivos USB \033[0m"
lsusb

echo -e "\033[1;31m:=> Informações da placa-mãe \033[0m"
dmidecode -t 2

echo -e "\033[1;31m:=> Informações do BIOS \033[0m"
dmidecode -t 0

echo -e "\033[1;31m:=> Informações do sistema operacional \033[0m"
lsb_release -a

echo -e "\033[1;31m:=> Informações do kernel \033[0m"
uname -a
}

INSTALLTOOLS()
{
echo -e "\033[32;1mUpdate do Sistema - Sem instalar atualizações\033[m"
apt update && apt upgrade -y

echo -e "\033[32;1mVerificando se o Net-Tools está instalado...\033[m"
apt install -y net-tools curl

echo -e "\033[32;1mVerificando se o Python 3 está instalado...\033[m"
apt install -y python3-pip

echo -e "\033[32;1mVerificando se o NMAP está instalado...\033[m"
apt install -y nmap

echo -e "\033[32;1mVerificando se o NIKTO está instalado...\033[m"
apt install -y nikto

echo -e "\033[32;1mVerificando se o GOBUSTER está instalado...\033[m"
apt install -y gobuster

echo -e "\033[32;1mVerificando se o HYDRA está instalado...\033[m"
apt install -y hydra

if [ -e $DirAtual/sslyze ]
  then
    echo -e "\033[32;1msslyze - Instalado!\033[m"
  else
    cd $DirAtual
    echo -e "\033[32;1mClonando o repositorio do sslyze\033[m"
    # git clone https://github.com/nabla-c0d3/sslyze
    pip install --upgrade pip setuptools wheel
    pip install --upgrade sslyze
  fi
}

SECLIST()
{
echo -e "\033[32;1mBaixar WordList Oficial Kali Linux.\033[m"
cd $DirAtual
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
ls SecLists/
}

INSTALLCOMP()
{
echo -e "\033[32;1mVamos instalar a biblioteca - TLD no Python\033[m"
echo -e "\033[32;1mVocê usa o pip, pip2 ou pip3?\033[m"
read pipinstall
$pipinstall install tld

echo -e "\033[32;1mVerificando se o GIT está instalado.\033[m"
apt update
apt install git -y
}

LSTFILE()
{
read lstsites
echo -e "\033[1;32mNome do arquivo: $lstsites\033[0m \033[1;31m \033[0m"
dir2="$dir/$lstsites"
mkdir $dir2
}

LOCALREDE()
{
echo -e "\033[32;1mOnde nós estamos?\033[m"
read lstsites
lstlocal=$lstsites
echo -e "\033[1;32mNome do local: $lstsites\033[0m \033[1;31m \033[0m"

dir3="$dir/$lstlocal"
mkdir $dir3
dirlista=$dir3
dir2=$dir3
}

DIRFILE()
{
read dirlista
echo -e "\033[1;32mDiretorio do arquivo: $dirlista\033[0m \033[1;31m \033[0m"
wc -l $dirlista'/'$lstsites
}

CLEARMEN()
{
unset ARRAY
}

TODAS()
{
   NIKTO
   NMAP
   GOBUSTER
   HYDRA
   SSLYZE
}

NIKTO()
{
    #Recebendo valores do arquivo ($lstsites.txt) em uma ARRAY
    while read line
    do
       [[ "$line" != '' ]] && ARRAY+=("$line")
    done < $dirlista/$lstsites

      #Percorrendo todos os valores do ARRAY
      for linha in "${ARRAY[@]}"
        do
          mkdir $dir2/$linha/
          echo -e "\033[32;1m ==== ($lstsites) - Nikto Full Scan ==== :=> $linha \033[m"
          echo " "
          nikto -Tuning 1234567890abc -h $linha -o $dir2/$linha/NIKTO_Tuning.html
          nikto -C all -h $linha -o $dir2/$linha/NIKTO_CALL.html
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
    done
}

NMAP()
{
    #Recebendo valores do arquivo ($lstsites.txt) em uma ARRAY
    while read line
    do
       [[ "$line" != '' ]] && ARRAY+=("$line")
    done < $dirlista/$lstsites

      #Percorrendo todos os valores do ARRAY
      for linha in "${ARRAY[@]}"
        do
          mkdir $dir2/$linha/ 
          echo -e "\033[32;1m ==== ($lstsites) - Gerar 20 IPs aleatorios e desconsiderar IPS e IDS ==== :=> $linha \033[m"
          echo " "
	       nmap -D RND:20 --open -sS -p- $linha -oA $dir2/$linha/PortasAbertas
          echo " "
          echo -e "\033[32;1m ==== ($lstsites) - Slow comprehensive scan ==== :=> $linha \033[m"
          echo " "
         #nmap -sS -sU -T4 -A -v -PE -PP -PS80,443,3306,8080 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" -oA $dir2/$linha/ShowcomprehensiveSCAN $linha
          nmap -sS -sU -T4 -A -v -PE -PP -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" -oA $dir2/$linha/ShowcomprehensiveSCAN $linha
          echo " "
          echo -e "\033[32;1m ==== ($lstsites) - Dados interessantes em ==== :=> $linha \033[m"
          echo " "
          #Mostra a razão da porta estar em determinado estado
          #Mostra todos os pacotes enviados e recebidos
          nmap --reason --packet-trace -sN -f -sV -oA $dir2/$linha/DadosInteressantes $linha
          echo " "
          echo -e "\033[32;1m ==== ($lstsites) - INTENSIVO ==== :=> $linha \033[m"
          echo " "
          nmap -T4 -A -v -oA $dir2/$linha/INTENSIVO $linha
          echo " "
          echo -e "\033[32;1m ==== ($lstsites) - VULNERABILIDADES ==== :=> $linha \033[m"
          echo " "
          nmap -T4 -A -v --script vuln -oA $dir2/$linha/VULNERAVEIS $linha
          echo " "
          echo -e "\033[32;1m ==== ($lstsites) - EXPLOIT ==== :=> $linha \033[m"
          echo " "
          nmap -T4 -A -v --script exploit -oA $dir2/$linha/EXPLOIT $linha
          echo " "
          echo -e "\033[32;1m ==== ($lstsites) - PACOTES EXTRAS ==== :=> $linha \033[m"
          echo " "
          #(Descobre a vulnerabilidade do servidor com aquele endereço de IP especificamente)
          #Analisando vulnerabilidades em mais endereços de IP de uma rede
          nmap -sS -v -Pn -A --open --script=vuln $linha -oA $dir2/$linha/EXTRA_AnaliseVulnerabilidades
          #Descobrindo portas abertas, versões de serviços e sistema operacional que está rodando no alvo.
          nmap -v -sV -Pn -O -open $linha -oA $dir2/$linha/EXTRA_PortasAbertasVersaoSO
          #(O argumento “-O” pode ser substituído pelo argumento “-A”)
          #Realizando pesquisas sobre alvos
          nmap -script=asn-query,whois-ip,ip-geolocation-maxmind $linha -oA $dir2/$linha/EXTRA_InformacoesGOIP
          #Burlando firewall
          #*Existem 4 maneiras diferentes de burlar um Firewall em uma rede externa:
          nmap -f -sV -A $linha -oA $dir2/$linha/EXTRA_BurlFirewallFragPacote # (Neste comando ocorre a fragmentação de pacotes que serão enviados para se conectar ao alvo)
          nmap -sS -sV -A $linha -oA $dir2/$linha/EXTRA_BurlFirewallSYN # (Faz varreduras do tipo SYN na rede alvo)
          nmap -Pn -sV -A $linha -oA $dir2/$linha/EXTRA_BurlFirewallNICMP # (Não enviar pacotes ICMP para o alvo, ou seja, não pingar na rede)
          nmap -sS -O -P0 -v $linha -oA $dir2/$linha/ScanFirewallFraco
          #Buscando falhas de DDoS
          nmap -sU -A -PN -n -pU:19,53,123,161 -script=ntp-monlist,dns-recursion,snmp-sysdescr $linha -oA $dir2/$linha/EXTRA_FalhasDDoS
          #Fazendo brute-force no banco de dados do alvo
          nmap --script=mysql-brute $linha -oA $dir2/$linha/EXTRA_BruteForceBD
          #Scan TOP
          nmap -sTUR -O -v -p 1-65535 -P0 $linha -oA $dir2/$linha/ScanPIPOCO
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
    done
}

GOBUSTER()
{
    #Recebendo valores do arquivo ($lstsites.txt) em uma ARRAY
    while read line
    do
       [[ "$line" != '' ]] && ARRAY+=("$line")
    done < $dirlista/$lstsites

      #Percorrendo todos os valores do ARRAY
      for linha in "${ARRAY[@]}"
        do
          mkdir $dir2/$linha/
          echo -e "\033[32;1m ==== ($lstsites) - GOBUSTER  ==== :=> $linha \033[m"
          echo -e "\033[32;1m Analisando o site ... \033[m"
          gobuster -u $linha -w $DirAtual/SecLists/Discovery/Web-Content/common.txt -q -n -e -o $dir2/$linha/Rel1_$linha
          gobuster -m dns -t 100 -u $linha -w $DirAtual/SecLists/Discovery/DNS/namelist.txt -o $dir2/$linha/Rel2_$linha
          gobuster -m dns -u $linha -w $DirAtual/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o $dir2/$linha/Rel3_$linha
          gobuster -m dns -u $linha -w $DirAtual/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -i -o $dir2/$linha/Rel4_$linha
          echo " "
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
      done
}

HYDRA()
{
    dirpass="$DirAtual/SecLists/Usernames/top-usernames-shortlist.txt"
    #Recebendo valores do arquivo ($lstsites.txt) em uma ARRAY
    while read line
    do
       [[ "$line" != '' ]] && ARRAY+=("$line")
    done < $dirlista/$lstsites

      #Percorrendo todos os valores do ARRAY
      for linha in "${ARRAY[@]}"
        do
          mkdir $dir2/$linha/
          echo -e "\033[32;1m ==== ($lstsites) - HYDRA  ==== :=> $linha \033[m"
          echo -e "\033[32;1m Analisando o site ... \033[m"
            while read user; do
               hydra -l $user -P $DirAtual/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt $linha ftp
               hydra -l $user -P $DirAtual/SecLists/Passwords/Common-Credentials/10k-most-common.txt $linha ssh
            done < $dirpass
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
      done
}

SSLYZE()
{
    #Recebendo valores do arquivo ($lstsites.txt) em uma ARRAY
    while read line
    do
       [[ "$line" != '' ]] && ARRAY+=("$line")
    done < $dirlista/$lstsites

      #Percorrendo todos os valores do ARRAY
      for linha in "${ARRAY[@]}"
        do
          mkdir $dir2/$linha/
          echo -e "\033[32;1m ==== ($lstsites) - sslyzev  ==== :=> $linha \033[m"
          echo -e "\033[32;1m Analisando o site ... \033[m"
          python -m sslyze $linha > $dir2/$linha/DadosSobreCertf_$linha.html
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
      done
}

SCANREDE()
{
#PARA O SCAN DA REDE
IP=$(ifconfig $i | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | tail -3 | head -1)
REDE=$(ip ro | egrep "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[1-3]{1,2}.*$i.*$IP" | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}")

nmap -p 80 $REDE -oG $dir3/nullbyte.txt
#Gera arquivo ($lstsites) contendo apenas IPs ONLINE
cat $dir3/nullbyte.txt | awk '/Up$/{print $2}' | cat >> $dir3/$lstsites
rm -r $dir3/nullbyte.txt
echo -e "\033[32;1m ==== Bllz! Já sei quais IPs ($lstsites) estão ONLINE na REDE  :=> $REDE ==== \033[m"

MEM="$(cat /proc/meminfo | grep "\MemTotal" | cut -d\: -f2-)"
MEM="$(echo ${MEM})"

# Coleta info processador - quantidade
NPROC="$(cat /proc/cpuinfo | grep -i processor | wc -l)"
NPROC="$(echo ${NPROC})"

# Coleta info processador - modelo
PROC="$(cat /proc/cpuinfo | grep "\model name" | tail -1 | cut -d\: -f2-)"
PROC="$(echo ${PROC})"

echo -e '\033[32;1m ==== Informações hardware ==== \033[m'

cat<<EOT
Hostname      : $(hostname)
Memoria       : ${MEM}
Processador   : [ ${NPROC} ] ${PROC}
EOT

echo " "
echo -e '\033[32;1m ==== Informações rede ==== \033[m'

# Coleta informacoes sobre rede
NIC=$(ip addr list | grep BROADCAST | awk -F ':' '{print $2}'| tr '\n' ' ')
#PARA O SCAN DA REDE

# Gateway
for i in $NIC
do
  IP=$(ifconfig $i | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | tail -3 | head -1)
  BCAST=$(ifconfig $i | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | tail -2 | head -1)
  MASK=$(ifconfig $i | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | tail -1 | head -1)
  REDE=$(ip ro | egrep "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[1-3]{1,2}.*$i.*$IP" | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}")
  MAC_ADDR=$(ifconfig $1 | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}')
ip ro | grep -o "default equalize" > /dev/null

if [ $? -eq 0 ]
then
  GW=$(ip ro | egrep  ".*nexthop.*$i" | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
else
  GW=$(ip ro | egrep  ".*default.*$i" | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")   
fi
  #Só aplica as etapas se forem dados da placa wlp6s0 (WiFi)
  if [ $IP != $IP ]
  then
    echo "Interface: $i"
    echo " "
  else
    echo "Interface .........: $i"
    echo "Endereco IP .......: $IP"
    echo "Endereco Fisico ...: $MAC_ADDR"
    echo "Broadcast .........: $BCAST"
    echo "Mascara:...........: $MASK"
    echo "Rede ..............: $REDE"
    echo "Gateway ...........: $GW"
    echo "Local de analise...: $lstsites"
    echo " "
   NIKTO
   NMAP
   GOBUSTER
   HYDRA
   SSLYZE
  fi
done

DNS=$(awk '/nameserver/ {print $2}' /etc/resolv.conf | tr -s '\n' ' ')
    echo -e "DNS Servers........: $DNS"
echo

}

##Bem Vindo##
#########################
##Inicio Bem Vindo##
clear && echo ""
echo "'########::'#######:::'#######::'##:::::::'##::::'##:::::::::::::::::::'###::::'##::::'##:'########:::'#######::"
echo "... ##..::'##.... ##:'##.... ##: ##:::::::. ##::'##:::::::::::::::::::'## ##:::. ##::'##:: ##.... ##:'##.... ##:"
echo "::: ##:::: ##:::: ##: ##:::: ##: ##::::::::. ##'##:::::::::::::::::::'##:. ##:::. ##'##::: ##:::: ##: ##::::..::"
echo "::: ##:::: ##:::: ##: ##:::: ##: ##:::::::::. ###:::::::'#######::::'##:::. ##:::. ###:::: ########:: ########::"
echo "::: ##:::: ##:::: ##: ##:::: ##: ##::::::::: ## ##::::::........:::: #########::: ## ##::: ##.. ##::: ##.... ##:"
echo "::: ##:::: ##:::: ##: ##:::: ##: ##:::::::: ##:. ##::::::::::::::::: ##.... ##:: ##:. ##:: ##::. ##:: ##:::: ##:"
echo "::: ##::::. #######::. #######:: ########: ##:::. ##:::::::::::::::: ##:::: ##: ##:::. ##: ##:::. ##:. #######::"
echo ":::..::::::.......::::.......:::........::..:::::..:::::::::::::::::..:::::..::..:::::..::..:::::..:::.......:::"
echo ""
echo -e "\033[1;32mSeja bem vindo ao ToolXMenu!\033[0m"
echo -e "\033[1;32mLinkedin:\033[0m https://www.linkedin.com/in/thalles-canela/"
echo -e "\033[1;32mYouTube: \033[0m https://www.youtube.com/c/aXR6CyberSecurity"
echo -e "\033[1;32mFacebook:\033[0m https://www.facebook.com/axr6PenTest"
echo -e "\033[1;32mGithub:  \033[0m https://github.com/ThallesCanela"
echo -e "\033[1;32mGithub:  \033[0m https://github.com/aXR6"
echo -e "\033[1;32mTwitter: \033[0m https://twitter.com/Axr6S"
echo -e "\033[1;32mPadim:   \033[0m https://www.padrim.com.br/aXR6CyberSecurity"
echo ""
echo -e "\033[1;32mO que você busca ficará aqui: $dir\033[0m \033[1;31m \033[0m"
echo -e "\033[1;32mDiretorio atual: $DirAtual\033[0m \033[1;31m \033[0m"
echo ""
echo -e "\033[1;31m:=> Não seja sujo! Se achou de graça, distribua de graça repassando os devidos créditos! \033[0m"
echo -e "\033[1;31m:=> Script ToolXMenu, desenvolvido por mim (Thalles Canela - ToolX), para organização das ferramentas encontradas em: \033[0m"
echo -e "\033[1;31m:=> https://github.com/aXR6 \033[0m"
echo ""
toolxmenu
##Fim Bem Vindo##
#######################
##/Bem Vindo##