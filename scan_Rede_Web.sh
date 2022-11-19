#!/bin/bash

DirAtual="${PWD}"
data=$(date +"%d_%m_%y_%A")
t=$(date +"%T")
dir="/home/$SUDO_USER/Documents/$data"
mkdir $dir

##toolxmenu##
##################
##START toolxmenu##
toolxmenu(){
   CLEARMEN
   PS3="└──> ToolXMenu : "
   options=("(1º Faça)-Instalação dos componentes" "(2º Faça)-Instalação das ferramentas" 
    "Testar a Rede (Toda a REDE)" "Testar Sites (Lista de SITES)" "SAIR")
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
         "SAIR")
            break
            ;;
         *) echo "A opção ($REPLY) não existe.";;
      esac
   done
}
##END toolxmenu##
################
##/toolxmenu##

##TOOLXSITE##
##################
##START TOOLXSITE##
TOOLXSITE(){
   CLEARMEN
   PS3="└──> ToolXMenu : "
   options=("(1º Faça)-Informe o Nome da lista (ex.: lst1.txt)" "(2º Faça)-Informe o Diretorio da Lista (ex.: $DirAtual)" 
    "Testar a lista com o NIKTO" "Testar a lista com o NMAP" "Testar a lista com o PHOTON" 
    "Testar a lista com o Fast-Google-Dorks-Scan" "Testar a lista com o uDork" "Testar a lista com o sslyze" "SAIR")
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
         "Testar a lista com o PHOTON")
            PHOTON
            ;;
         "Testar a lista com o Fast-Google-Dorks-Scan")
            FastGoogleDorksScan
            ;;
         "Testar a lista com o uDork")
            uDork
            ;;
         "Testar a lista com o sslyze")
            sslyze
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
TOOLXREDE(){
   CLEARMEN
   PS3="└──> ToolXMenu : "
   options=("Onde nós estamos?" "Verificar a rede" "SAIR")
   select opt in "${options[@]}"
   do
      case $opt in
         "Onde nós estamos?")
            LOCALREDE
            ;;
         "Verificar a rede")
            SCANREDE
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

INSTALLTOOLS()
{
echo -e "\033[32;1mUpdate do Sistema - Sem instalar atualizações\033[m"
apt-get update

echo -e "\033[32;1mVerificando se o NMAP está instalado...\033[m"
apt-get install nmap -y

echo -e "\033[32;1mVerificando se o NIKTO está instalado...\033[m"
apt-get install nikto -y

echo -e "\033[32;1mVerificando se o AHA está instalado...\033[m"
apt-get install aha


if [ -e $DirAtual/Photon ]
  then
    echo -e "\033[32;1mPhoton - Instalado!\033[m"
  else
    cd $DirAtual
    echo -e "\033[32;1mClonando o repositorio do Python no GitHub\033[m"
    git clone https://github.com/s0md3v/Photon.git
  fi

if [ -e $DirAtual/Fast-Google-Dorks-Scan ]
  then
    echo -e "\033[32;1mFast-Google-Dorks-Scan - Instalado!\033[m"
  else
    cd $DirAtual
    echo -e "\033[32;1mClonando o repositorio do Fast-Google-Dorks-Scan\033[m"
    git clone https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan
  fi

if [ -e $DirAtual/uDork ]
  then
    echo -e "\033[32;1muDork - Instalado!\033[m"
  else
    cd $DirAtual
    echo -e "\033[32;1mClonando o repositorio do Fast-Google-Dorks-Scan\033[m"
    git clone https://github.com/m3n0sd0n4ld/uDork
  fi

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

   bash chmod -R 777 $DirAtual*

}

INSTALLCOMP()
{
echo -e "\033[32;1mVamos instalar a biblioteca - TLD no Python\033[m"
echo -e "\033[32;1mVocê usa o pip, pip2 ou pip3?\033[m"
read pipinstall
$pipinstall install tld requests requests[socks] urllib3 tld

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
          nikto -Tuning 1234567890abc -h $linha -p 80,8080,443 -o $dir2/$linha/NIKTO_Tuning.html
          nikto -C all -h $linha -p 80,8080,443 -o $dir2/$linha/NIKTO_CALL.html
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
          nmap -sS -sU -T4 -A -v -PE -PP -PS80,443,3306,8080 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" -oA $dir2/$linha/ShowcomprehensiveSCAN $linha
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

PHOTON()
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
          echo -e "\033[32;1m ==== ($lstsites) - Photon Full Scan ==== :=> $linha \033[m"
          echo " "
          python3 $DirAtual/Photon/photon.py -u $linha -l 3 -t 100 --wayback -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha --clone -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha -l 3 -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha -t 10 -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha -d 2 -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha --timeout=4 -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha -c "PHPSESSID=u5423d78fqbaju9a0qke25ca87" -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha --user-agent "curl/7.35.0,Wget/1.15 (linux-gnu)" -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha --regex "\d{10}" -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha --wayback -o $dir2/$linha
          python3 $DirAtual/Photon/photon.py -u $linha --keys -o $dir2/$linha
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
      done
}

FastGoogleDorksScan()
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
          echo -e "\033[32;1m ==== ($lstsites) - Fast-Google-Dorks-Scan  ==== :=> $linha \033[m"
          echo -e "\033[32;1m Analisando o site ... \033[m"
          bash Fast-Google-Dorks-Scan/FGDS.sh $linha ls --color=always | aha --black --title 'FGDS' > $dir2/$linha/FGDS.html
          echo " "
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
      done
}

uDork()
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
          echo -e "\033[32;1m ==== ($lstsites) - uDork  ==== :=> $linha \033[m"
          echo -e "\033[32;1m Analisando o site ... \033[m"
          bash uDork/uDork.sh $linha -e all -p 5 ls --color=always | aha --black --title 'uDork_ArquivosOcultos' > $dir2/$linha/ArquivosOcultos.html
          bash uDork/uDork.sh $linha -t all -p 5 ls --color=always | aha --black --title 'uDork_ErrosIndicados' > $dir2/$linha/ErrosIndicados.html
          bash uDork/uDork.sh $linha -u all -p 5 ls --color=always | aha --black --title 'uDork_StringNasURLs' > $dir2/$linha/StringNasURLs.html
          bash uDork/uDork.sh $linha -g all -p 5 ls --color=always | aha --black --title 'uDork_ResultDork' > $dir2/$linha/ResultDork.html
          echo " "
          #Removendo valor lido
          #unset ARRAY
          #Removendo o arquivo lido ($lstsites.txt)
          #rm -r $dir2/$lstsites.txt
      done
}

sslyze()
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
          python -m sslyze $linha ls --color=always | aha --black --title 'Dados_Sobre_Certificado' > $dir2/$linha/DadosSobreCertf.html
          echo " "
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
	NMAP
    NIKTO
    PHOTON
    FastGoogleDorksScan
    uDork
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
