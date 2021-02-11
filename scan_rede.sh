#!/bin/bash 
clear

opt="/opt/Photon"

echo -e "\033[32;1mOnde nós estamos?\033[m"
read local

echo -e "\033[32;1mVerificando se o NMAP está instalado...\033[m"
apt-get install nmap -y

echo -e "\033[32;1mVerificando se o NIKTO está instalado...\033[m"
apt-get install nikto -y

if [ -e $opt ]
	then
		echo -e "\033[32;1mVamos instalar a biblioteca - TLD no Python\033[m"
		echo -e "\033[32;1mVocê usa o pip, pip2 ou pip3?\033[m"
			read pipinstall
			$pipinstall install tld
	else
		echo -e "\033[32;1mVerificando se o GIT está instalado.\033[m"
			apt update
			apt install git -y
			cd "/opt"
		echo -e "\033[32;1mClonando o repositorio do Python no GitHub\033[m"
			git clone https://github.com/s0md3v/Photon.git
		echo -e "\033[32;1mVamos instalar a biblioteca - TLD no Python\033[m"
		echo -e "\033[32;1mVocê usa o pip, pip2 ou pip3?\033[m"
			read pipinstall
			$pipinstall install tld
	fi

clear

data=$(date +"%d_%m_%y_%A")
t=$(date +"%T")

dir="/home/$SUDO_USER/Documentos/$data/"
dir2="$dir/$local"

mkdir $dir
mkdir $dir2

IP=$(ifconfig $i | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | tail -3 | head -1)
REDE=$(ip ro | egrep "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[1-3]{1,2}.*$i.*$IP" | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}")

nmap -p 80 $REDE -oG $dir2/nullbyte.txt
#Gera arquivo ($local.txt) contendo apenas IPs ONLINE
cat $dir2/nullbyte.txt | awk '/Up$/{print $2}' | cat >> $dir2/$local.txt
rm -r $dir2/nullbyte.txt
echo -e "\033[32;1m ==== Bllz! Já sei quais IPs ($local) estão ONLINE na REDE  :=> $REDE ==== \033[m"

MEM="$(cat /proc/meminfo | grep "\MemTotal" | cut -d\: -f2-)"
MEM="$(echo ${MEM})"

# Coleta info processador - quantidade
NPROC="$(cat /proc/cpuinfo | grep -i processor | wc -l)"
NPROC="$(echo ${NPROC})"

# Coleta info processador - modelo
PROC="$(cat /proc/cpuinfo | grep "\model name" | tail -1 | cut -d\: -f2-)"
PROC="$(echo ${PROC})"

# Coleta info discos
DISK=$(fdisk -l | grep Disk | egrep -v "identifier" | cut -d ' ' -f2-4 | cut -d ',' -f1)
echo " "
echo -e '\033[32;1m ==== Informações hardware ==== \033[m'

cat<<EOT
Hostname      : $(hostname)
Memoria       : ${MEM}
Processador   : [ ${NPROC} ] ${PROC}
Disco(s)      : $DISK
EOT

echo " "
echo -e '\033[32;1m ==== Informações rede ==== \033[m'

# Coleta informacoes sobre rede
NIC=$(ip addr list | grep BROADCAST | awk -F ':' '{print $2}'| tr '\n' ' ')

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
		echo "Endereco IP .......: -----"
		echo " "
	else
		echo "Interface .........: $i"
		echo "Endereco IP .......: $IP"
		echo "Endereco Fisico ...: $MAC_ADDR"
		echo "Broadcast .........: $BCAST"
		echo "Mascara:...........: $MASK"
		echo "Rede ..............: $REDE"
		echo "Gateway ...........: $GW"
		echo "Local de analise...: $local"
		echo " "

		#Recebendo valores do arquivo ($local.txt) em uma ARRAY
		while read line
		do
		   [[ "$line" != '' ]] && ARRAY+=("$line")
		done < $dir2/$local.txt

		#Percorrendo todos os valores do ARRAY
		for linha in "${ARRAY[@]}"
		do
		python3 $opt/photon.py -u $linha -l 3 -t 100 --wayback -o $dir2/$linha
		python3 $opt/photon.py -u $linha -o $dir2/$linha
		python3 $opt/photon.py -u $linha --clone -o $dir2/$linha
		python3 $opt/photon.py -u $linha -l 3 -o $dir2/$linha
		python3 $opt/photon.py -u $linha -t 10 -o $dir2/$linha
		python3 $opt/photon.py -u $linha -d 2 -o $dir2/$linha
		python3 $opt/photon.py -u $linha --timeout=4 -o $dir2/$linha
		python3 $opt/photon.py -u $linha -c "PHPSESSID=u5423d78fqbaju9a0qke25ca87" -o $dir2/$linha
		python3 $opt/photon.py -u $linha --user-agent "curl/7.35.0,Wget/1.15 (linux-gnu)" -o $dir2/$linha
		python3 $opt/photon.py -u $linha --regex "\d{10}" -o $dir2/$linha
		python3 $opt/photon.py -u $linha --wayback -o $dir2/$linha
		python3 $opt/photon.py -u $linha --keys -o $dir2/$linha

		echo -e "\033[32;1m ==== ($local) - Verificando a máquina ==== :=> $linha \033[m"
		echo " "
		echo -e "\033[32;1m ==== ($local) - Slow comprehensive scan ==== :=> $linha \033[m"
		echo " "
		nmap -sS -sU -T4 -A -v -PE -PP -PS80,443,3306,8080 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" -oA $dir2/$linha/ShowcomprehensiveSCAN $linha
		echo " "
		echo -e "\033[32;1m ==== ($local) - Dados interessantes em ==== :=> $linha \033[m"
		echo " "
		#Mostra a razão da porta estar em determinado estado
		#Mostra todos os pacotes enviados e recebidos
		nmap --reason --packet-trace -sN -f -sV -oA $dir2/$linha/DadosInteressantes $linha
		echo " "
		echo -e "\033[32;1m ==== ($local) - INTENSIVO ==== :=> $linha \033[m"
		echo " "
		nmap -T4 -A -v -oA $dir2/$linha/INTENSIVO $linha
		echo " "
		echo -e "\033[32;1m ==== ($local) - VULNERABILIDADES ==== :=> $linha \033[m"
		echo " "
		nmap -T4 -A -v --script vuln -oA $dir2/$linha/VULNERAVEIS $linha
		echo " "
		echo -e "\033[32;1m ==== ($local) - EXPLOIT ==== :=> $linha \033[m"
		echo " "
		nmap -T4 -A -v --script exploit -oA $dir2/$linha/EXPLOIT $linha
		echo " "

		echo -e "\033[32;1m ==== ($local) - PACOTES EXTRAS ==== :=> $linha \033[m"
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
		#*Existem 3 maneiras diferentes de burlar um Firewall em uma rede externa:
		nmap -f -sV -A $linha -oA $dir2/$linha/EXTRA_BurlFirewallFragPacote # (Neste comando ocorre a fragmentação de pacotes que serão enviados para se conectar ao alvo)
		nmap -sS -sV -A $linha -oA $dir2/$linha/EXTRA_BurlFirewallSYN # (Faz varreduras do tipo SYN na rede alvo)
		nmap -Pn -sV -A $linha -oA $dir2/$linha/EXTRA_BurlFirewallNICMP # (Não enviar pacotes ICMP para o alvo, ou seja, não pingar na rede)

		#Buscando falhas de DDoS
		nmap -sU -A -PN -n -pU:19,53,123,161 -script=ntp-monlist,dns-recursion,snmp-sysdescr $linha -oA $dir2/$linha/EXTRA_FalhasDDoS

		#Fazendo brute-force no banco de dados do alvo
		nmap --script=mysql-brute $linha -oA $dir2/$linha/EXTRA_BruteForceBD

		echo -e "\033[32;1m ==== ($local) - Verificando os servidores WEB. ==== :=> $linha \033[m"
		echo " "
		nikto -Tuning 1234567890abc -h $linha -p 80,8080,443 -o $dir2/$linha/NIKTO_Tuning.html
		nikto -C all -h $linha -p 80,8080,443 -o $dir2/$linha/NIKTO_CALL.html
		echo " "

		#Removendo valor lido
		unset ARRAY
		#Removendo o arquivo lido ($local.txt)
		#rm -r $dir2/$local.txt
		done
	fi
done

DNS=$(awk '/nameserver/ {print $2}' /etc/resolv.conf | tr -s '\n' ' ')
		echo -e "DNS Servers........: $DNS"
echo
