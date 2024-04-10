#!/bin/bash

# Função para capturar e exibir erros, registrando-os em um arquivo de log
handle_error() {
    local EXIT_STATUS=$1
    local ERROR_LINE=$2
    # Determina o diretório do script atual
    local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
    local LOG_DIR="$SCRIPT_DIR/logs"
    local LOG_FILE="$LOG_DIR/error_log_$(date +%d-%m-%Y-%H-%M-%S).log"
    
    # Verifica se o diretório de log existe, se não, cria um
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
    fi

    # Mensagem de erro a ser registrada
    local ERROR_MESSAGE="Erro detectado
Status de saída: $EXIT_STATUS
Erro na linha: $ERROR_LINE
Comando: ${BASH_COMMAND}
Data: $(date +'%d-%m-%Y %H:%M:%S')"

    # Exibe a mensagem de erro no stderr
    echo -e "\033[1;31m$ERROR_MESSAGE\033[0m" >&2

    # Registra a mensagem de erro no arquivo de log
    echo "$ERROR_MESSAGE" >> "$LOG_FILE"
}

# Captura de erro com a trap
trap 'handle_error $? $LINENO' ERR

DirAtual=("${PWD}")
data=$(date +"%d_%m_%y_%A")
t=$(date +"%T")
# Verificando se o script está sendo executado com privilégios de superusuário (sudo)
if [ -n "$SUDO_USER" ]; then
    # Se sim, usar a variável $SUDO_USER
    dir="/home/$SUDO_USER/Documentos/$data"
else
    # Se não, usar a variável $USER
    dir="/home/$USER/Documentos/$data"
fi
if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    echo "Diretório criado: $dir"
else
    echo "Diretório já existe: $dir"
fi

##toolxmenu##
##################
##START toolxmenu##
toolxmenu() {
   CLEARMEN
   PS3=("└──> ToolXMenu : ")
   options=(
   	"(1º Faça)-Instalação dos componentes"
   	"(2º Faça)-Instalação das ferramentas"
   	"Testar a Rede (Toda a REDE)"
   	"Testar Sites (Lista de SITES)"
   	"Baixar WordList Oficial Kali Linux"
   	"Informações sobre Hardware e SO"
      "Criar um ambiente virtual"
   	"SAIR")
	    select opt in "${options[@]}"
	    do
	      case $opt in
		 "(1º Faça)-Instalação dos componentes")
		    INSTALLCOMP
		    ;;
		 "(2º Faça)-Instalação das ferramentas")
		    INSTALLTOOLS
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
       "Criar um ambiente virtual")
          AMBVIRT
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

AMBVIRT(){
   # Define o diretório do ambiente virtual
   VENV_DIR="/tmp/venv"

   # Checa se o ambiente virtual já existe, se não, cria um
   if [ ! -d "$VENV_DIR" ]; then
      python3 -m venv "$VENV_DIR"
      echo -e "Ambiente temporario criado."
   fi

   # Ativa o ambiente virtual
   source "$VENV_DIR/bin/activate"
   echo -e "Ambiente ativado. Só curtir..."
   
}

INFOMAQUINA() {
  echo -e "\033[1;31m:=> Informações do sistema: \033[0m"

  echo -e "\033[1;31m:=> Informações do CPU \033[0m"
  grep "model name\|vendor_id\|cpu cores" /proc/cpuinfo | sort -u

  echo -e "\033[1;31m:=> Informações da memória \033[0m"
  free -h

  echo -e "\033[1;31m:=> Informações dos discos \033[0m"
  df -hT | grep -vE 'tmpfs|udev'

  echo -e "\033[1;31m:=> Informações dos dispositivos PCI \033[0m"
  lspci

  echo -e "\033[1;31m:=> Informações dos dispositivos USB \033[0m"
  lsusb

  if command -v dmidecode &> /dev/null; then
    echo -e "\033[1;31m:=> Informações da placa-mãe \033[0m"
    sudo dmidecode -t 2

    echo -e "\033[1;31m:=> Informações do BIOS \033[0m"
    sudo dmidecode -t 0
  else
    echo -e "\033[1;33mDmidecode não está instalado. Algumas informações não podem ser exibidas.\033[0m"
  fi

  if command -v lsb_release &> /dev/null; then
    echo -e "\033[1;31m:=> Informações do sistema operacional \033[0m"
    lsb_release -a
  else
    echo -e "\033[1;33mlsb_release não está disponível. Exibindo informações do /etc/os-release.\033[0m"
    cat /etc/os-release
  fi

  echo -e "\033[1;31m:=> Informações do kernel \033[0m"
  uname -r
}

INSTALLTOOLS()
{
echo -e "\033[32;1mUpdate do Sistema - Sem instalar atualizações\033[m"
apt update && apt upgrade -y

echo -e "\033[32;1mVerificando se o Net-Tools está instalado...\033[m"
apt install -y net-tools curl

echo -e "\033[32;1mVerificando se o Python 3 está instalado...\033[m"
apt install -y python3-pip python3.11-venv

echo -e "\033[32;1mVerificando se o NMAP está instalado...\033[m"
apt install -y nmap

echo -e "\033[32;1mVerificando se o NIKTO está instalado...\033[m"
# Define o local de instalação do Nikto
INSTALL_DIR="/opt/nikto"

# Clona o repositório do Nikto
echo "Clonando o repositório do Nikto..."
sudo git clone https://github.com/sullo/nikto.git "$INSTALL_DIR"

# Verifica se o clone foi bem-sucedido
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Falha ao clonar o repositório do Nikto. Verifique suas permissões."
    exit 1
fi

# Torna o script do Nikto executável
echo "Tornando o Nikto executável..."
sudo chmod +x "$INSTALL_DIR/program/nikto.pl"

# Cria um link simbólico para tornar o Nikto acessível globalmente
echo "Criando um link simbólico para o Nikto..."
sudo ln -sf "$INSTALL_DIR/program/nikto.pl" /usr/local/bin/nikto

echo -e "\033[32;1mVerificando se o GOBUSTER está instalado...\033[m"
apt install -y gobuster

echo -e "\033[32;1mVerificando se o HYDRA está instalado...\033[m"
apt install -y hydra

# Define a função para instalar o sslyze
function install_sslyze {
  echo -e "\033[32;1mClonando o repositorio do sslyze\033[m"
  # git clone https://github.com/nabla-c0d3/sslyze
  pip install --upgrade pip setuptools wheel --break-system-packages
  pip install --upgrade sslyze --break-system-packages
}

# Verifica se o sslyze está instalado e exibe uma mensagem
if [ -e "$DirAtual/sslyze" ]; then
  echo -e "\033[32;1msslyze - Instalado!\033[m"
else
  cd "$DirAtual"
  install_sslyze
fi
}

SECLIST()
{
echo -e "\033[32;1mBaixar WordList Oficial Kali Linux.\033[m"
cd $DirAtual
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
ls SecLists/
}

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
scan_network $(echo $ip_address | cut -d '.' -f 1-3) >> $dir3/$lstsites
echo -e "\033[32;1mTrabalho concluído. \033[m"
cat $dir3/$lstsites
}

INSTALLCOMP()
{
echo -e "\033[32;1mVamos instalar a biblioteca - TLD no Python\033[m"
echo -e "\033[32;1mVocê usa o pip, pip2 ou pip3?\033[m"
read pipinstall
$pipinstall install --root-user-action=ignore tld --break-system-packages

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

NIKTO() {
  # Verificar se o diretório e o arquivo de lista de sites existem
  if [ ! -d "$dirlista" ] || [ ! -f "$dirlista/$lstsites" ]; then
    echo -e "\033[31;1mDiretório ou arquivo de lista de sites não encontrado.\033[m"
    return 1 # Sair da função com erro
  fi

  # Ler valores do arquivo em uma array
  while IFS= read -r line; do
    [[ "$line" != '' ]] && ARRAY+=("$line")
  done < "$dirlista/$lstsites"

  # Verificar se ARRAY está vazio
  if [ ${#ARRAY[@]} -eq 0 ]; then
    echo -e "\033[31;1mNenhum site para escanear.\033[m"
    return 1 # Sair da função com erro
  fi

  # Percorrer todos os valores do ARRAY
  for linha in "${ARRAY[@]}"; do
    mkdir -p "$dir2/$linha/"
    echo -e "\033[32;1m ==== ($lstsites) - Nikto Full Scan ==== :=> $linha \033[m"
    echo " "

    nikto -Tuning 1234567890abc -h "$linha" -o "$dir2/$linha/NIKTO_Tuning.html"
    nikto -C all -h "$linha" -o "$dir2/$linha/NIKTO_CALL.html"
  done

  # Nota: Remoção de dados e arquivo foi comentada, descomente se necessário.
  #unset ARRAY
  #rm -r "$dir2/$lstsites.txt"
}


NMAP()
{
    # Recebendo valores do arquivo ($lstsites.txt) em uma ARRAY
    while read line
    do
        [[ "$line" != '' ]] && ARRAY+=("$line")
    done < "$dirlista/$lstsites"

    # Percorrendo todos os valores do ARRAY
    for linha in "${ARRAY[@]}"
    do
        mkdir -p "$dir2/$linha/"
        echo -e "\033[32;1m ==== ($lstsites) - Gerar 20 IPs aleatórios e desconsiderar IPS e IDS ==== :=> $linha \033[m"
        echo " "
        nmap -D RND:20 --open -sS -p- "$linha" -oA "$dir2/$linha/PortasAbertas"
        echo " "
        echo -e "\033[32;1m ==== ($lstsites) - Slow comprehensive scan ==== :=> $linha \033[m"
        echo " "
        nmap -sS -sU -T4 -A -v -PE -PP -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" -oA "$dir2/$linha/ShowcomprehensiveSCAN" "$linha"
        echo " "
        echo -e "\033[32;1m ==== ($lstsites) - Dados interessantes em ==== :=> $linha \033[m"
        echo " "
        nmap --reason --packet-trace -sN -f -sV -oA "$dir2/$linha/DadosInteressantes" "$linha"
        echo " "
        echo -e "\033[32;1m ==== ($lstsites) - INTENSIVO ==== :=> $linha \033[m"
        echo " "
        nmap -T4 -A -v -oA "$dir2/$linha/INTENSIVO" "$linha"
        echo " "
        echo -e "\033[32;1m ==== ($lstsites) - VULNERABILIDADES ==== :=> $linha \033[m"
        echo " "
        nmap -T4 -A -v --script vuln -oA "$dir2/$linha/VULNERAVEIS" "$linha"
        echo " "
        echo -e "\033[32;1m ==== ($lstsites) - EXPLOIT ==== :=> $linha \033[m"
        echo " "
        nmap -T4 -A -v --script exploit -oA "$dir2/$linha/EXPLOIT" "$linha"
        echo " "
        echo -e "\033[32;1m ==== ($lstsites) - PACOTES EXTRAS ==== :=> $linha \033[m"
        echo " "
        nmap -sS -v -Pn -A --open --script=vuln "$linha" -oA "$dir2/$linha/EXTRA_AnaliseVulnerabilidades"
        nmap -v -sV -Pn -O --open "$linha" -oA "$dir2/$linha/EXTRA_PortasAbertasVersaoSO"
        nmap -script=asn-query,whois-ip,ip-geolocation-maxmind "$linha" -oA "$dir2/$linha/EXTRA_InformacoesGOIP"
        nmap -f -sV -A "$linha" -oA "$dir2/$linha/EXTRA_BurlFirewallFragPacote"
        nmap -sS -sV -A "$linha" -oA "$dir2/$linha/EXTRA_BurlFirewallSYN"
        nmap -Pn -sV -A "$linha" -oA "$dir2/$linha/EXTRA_BurlFirewallNICMP"
        nmap -sS -O -Pn -v "$linha" -oA "$dir2/$linha/ScanFirewallFraco"
        nmap -sU -A -Pn -n -pU:19,53,123,161 -script=ntp-monlist,dns-recursion,snmp-sysdescr "$linha" -oA "$dir2/$linha/EXTRA_FalhasDDoS"
        nmap --script=mysql-brute "$linha" -oA "$dir2/$linha/EXTRA_BruteForceBD"
        nmap -sTUR -O -v -p 1-65535 -Pn "$linha" -oA "$dir2/$linha/ScanPIPOCO"
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

cidr_to_netmask() {
    local cidr=$1
    local mask=$((0xffffffff << (32 - cidr)))
    printf "%d.%d.%d.%d\n" $((mask >> 24 & 0xff)) $((mask >> 16 & 0xff)) $((mask >> 8 & 0xff)) $((mask & 0xff))
}

SCANREDE() {
    echo -e '\033[32;1m ==== Iniciando Scan da Rede ==== \033[m'

    for i in $(ip addr list | grep BROADCAST | awk -F ':' '{print $2}' | tr -d ' '); do
        IP=$(ip a show $i | grep -oP 'inet \K[\d.]+' | head -1)
        CIDR=$(ip a show $i | grep -oP 'inet \K[\d.]+/\d+' | awk -F'/' '{print $2}' | head -1)
        MASK=$(cidr_to_netmask $CIDR)
        REDE=$(ip route | grep -oP "[\d.]+/\d+.*dev $i proto kernel" | awk '{print $1}')
        MAC_ADDR=$(ip link show $i | grep -oP 'link/ether \K[\da-f:]+')

        # Define o Gateway
        GW=$(ip route | grep default | grep $i | awk '{print $3}')

        if [ -z "$IP" ]; then
            continue
        fi

        echo -e "\033[32;1m ==== Informações da Interface: $i ==== \033[m"
        echo "Endereço IP .......: $IP"
        echo "Endereço Físico ...: $MAC_ADDR"
        echo "Máscara ...........: $MASK"
        echo "Rede ..............: $REDE"
        echo "Gateway ...........: $GW"
        echo

        # Executar o Nmap
        nmap -p 80 $REDE -oG "$dir3/nullbyte.txt"
        awk '/Up$/{print $2}' "$dir3/nullbyte.txt" >> "$dir3/$lstsites"
        rm -f "$dir3/nullbyte.txt"
        echo -e "\033[32;1m ==== IPs ONLINE na REDE $REDE identificados em $lstsites ==== \033[m"

    done

    # DNS
    DNS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | tr '\n' ' ')
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
