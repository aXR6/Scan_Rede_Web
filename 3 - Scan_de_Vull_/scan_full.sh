#!/bin/bash

# Armazena o diretório atual
DirAtual="${PWD}"
# Formata a data e o tempo
data=$(date +"%d_%m_%y_%A")
t=$(date +"%T")

# Verifica se o script está sendo executado como root
if [ "$(id -u)" -eq 0 ]; then
    # Para execução como root, usa SUDO_USER para encontrar o usuário que invocou o sudo
    if [ -n "$SUDO_USER" ]; then
        # Se estiver rodando com sudo, define o diretório de destino baseando-se em SUDO_USER
        dir="/home/$SUDO_USER/Documentos/$data"
    else
        # Caso contrário, assume root como usuário diretamente (cenário menos comum)
        dir="/root/Documentos/$data"
    fi
else
    # Para execução como usuário comum
    dir="/home/$USER/Documentos/$data"
fi

# Verifica se o diretório já existe antes de tentar criá-lo
if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    echo "Diretório criado: $dir"
else
    echo "O diretório já existe: $dir"
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

INFOMAQUINA() {
    echo -e "\033[1;31m:=> Informações do sistema: \033[0m"

    echo -e "\033[1;31m:=> Informações do CPU \033[0m"
    awk -F': ' '/model name|vendor_id|cpu cores/ {print $2}' /proc/cpuinfo | sort -u

    echo -e "\033[1;31m:=> Informações da memória \033[0m"
    free -m

    echo -e "\033[1;31m:=> Informações dos discos \033[0m"
    df -h

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
        echo "dmidecode não está instalado. Não é possível mostrar informações da placa-mãe e do BIOS."
    fi

    echo -e "\033[1;31m:=> Informações do sistema operacional \033[0m"
    if command -v lsb_release &> /dev/null; then
        lsb_release -a
    else
        echo "lsb_release não está instalado. Não é possível mostrar informações do sistema operacional."
    fi

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

# Define a função para instalar o sslyze
function install_sslyze {
  echo -e "\033[32;1mClonando o repositorio do sslyze\033[m"
  # git clone https://github.com/nabla-c0d3/sslyze
  pip install --upgrade pip setuptools wheel
  pip install --upgrade sslyze
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

DETECTSERVICE() {
    # Cria um diretório temporário para armazenar os resultados
    dir3=$(mktemp -d)
    # Define um nome de arquivo para listar os sites
    lstsites="list_of_services.txt"

    # Função para detectar serviços em um único IP
    function detect_services {
        local host=$1
        nmap -n -sV "$host" | grep 'open' | awk '{print $1,$3,$4}' > "$dir3/${host}_services.txt"
        if [ -s "$dir3/${host}_services.txt" ]; then
            while read service; do
                echo "$host: $service"
            done < "$dir3/${host}_services.txt"
        fi
    }

    # Função para escanear a rede e detectar hosts ativos
    function scan_network {
        local base_ip=$1
        echo "Iniciando escaneamento na rede $base_ip.0/24..."
        nmap -n -sP "${base_ip}.0/24" | awk '/is up/ {print up}; {gsub (/\(|\)/,""); up = $NF}' | while read host; do
            echo "Detectando serviços em $host..."
            detect_services $host &
        done
        wait
    }

    # Solicita ao usuário o endereço de IP inicial
    read -p "Digite o endereço de IP inicial (ex: 192.168.1): " ip_address

    # Inicia a detecção de serviços online
    scan_network "$(echo $ip_address | cut -d '.' -f 1-3)"

    echo -e "\033[32;1mTrabalho concluído.\033[m"
    # Combina os arquivos de resultados individuais em um único arquivo
    cat "$dir3"/*_services.txt > "$dir3/$lstsites"
    # Mostra o conteúdo do arquivo de resultados
    cat "$dir3/$lstsites"
    # Limpeza: remover diretório temporário se necessário
    # rm -r "$dir3"
}

INSTALLCOMP()
{
echo -e "\033[32;1mVamos instalar a biblioteca - TLD no Python\033[m"
echo -e "\033[32;1mVocê usa o pip, pip2 ou pip3?\033[m"
read pipinstall
$pipinstall install --root-user-action=ignore tld

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
    # Checando se o diretório da lista existe
    if [ ! -d "$dirlista" ]; then
        echo "O diretório $dirlista não existe."
        return 1 # Retorna falha
    fi

    # Checando se o arquivo de lista de sites existe
    if [ ! -f "$dirlista/$lstsites" ]; then
        echo "O arquivo de lista $dirlista/$lstsites não existe."
        return 1 # Retorna falha
    fi

    # Lendo valores do arquivo ($lstsites.txt) para um array
    while IFS= read -r line; do
        [[ "$line" != '' ]] && ARRAY+=("$line")
    done < "$dirlista/$lstsites"

    # Percorrendo todos os valores do array
    for linha in "${ARRAY[@]}"; do
        # Criando diretório se não existir
        mkdir -p "$dir2/$linha/"

        echo -e "\033[32;1m ==== ($lstsites) - Nikto Full Scan ==== :=> $linha \033[m"
        echo " "

        # Executando varreduras com nikto e salvando os resultados
        nikto -Tuning 1234567890abc -h "$linha" -o "$dir2/$linha/NIKTO_Tuning.html"
        nikto -C all -h "$linha" -o "$dir2/$linha/NIKTO_CALL.html"
    done

    # Nota: Removido unset ARRAY e rm -r $dir2/$lstsites.txt para manter os dados para uso futuro.
}

NMAP() {
    # Verificando se o diretório e o arquivo de lista existem
    if [[ ! -d "$dirlista" ]] || [[ ! -f "$dirlista/$lstsites" ]]; then
        echo "Diretório ou arquivo de lista não encontrado."
        return 1
    fi

    # Limpando a ARRAY antes de começar
    ARRAY=()

    # Lendo valores do arquivo ($lstsites.txt) em uma ARRAY
    while IFS= read -r line; do
        [[ -n "$line" ]] && ARRAY+=("$line")
    done < "$dirlista/$lstsites"

    # Percorrendo todos os valores do ARRAY
    for linha in "${ARRAY[@]}"; do
        mkdir -p "$dir2/$linha/"
        echo -e "\033[32;1m ==== ($lstsites) - Gerar 20 IPs aleatorios e desconsiderar IPS e IDS ==== :=> $linha \033[m\n"

        nmap -D RND:20 --open -sS -p- "$linha" -oA "$dir2/$linha/PortasAbertas"
        echo -e "\n\033[32;1m ==== ($lstsites) - Slow comprehensive scan ==== :=> $linha \033[m\n"

        nmap -sS -sU -T4 -A -v -PE -PP -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" -oA "$dir2/$linha/ShowcomprehensiveSCAN" "$linha"
        echo -e "\n\033[32;1m ==== ($lstsites) - Dados interessantes em ==== :=> $linha \033[m\n"

        nmap --reason --packet-trace -sN -f -sV -oA "$dir2/$linha/DadosInteressantes" "$linha"
        echo -e "\n\033[32;1m ==== ($lstsites) - INTENSIVO ==== :=> $linha \033[m\n"

        nmap -T4 -A -v --script vuln -oA "$dir2/$linha/VULNERAVEIS" "$linha"
        echo -e "\n\033[32;1m ==== ($lstsites) - EXPLOIT ==== :=> $linha \033[m\n"

        nmap -T4 -A -v --script exploit -oA "$dir2/$linha/EXPLOIT" "$linha"
        # Adicione aqui demais comandos conforme necessário, seguindo o padrão acima

        # O comando `unset ARRAY` foi removido, pois não é necessário se a função só será chamada uma vez por execução do script
        # O comando `rm -r $dir2/$lstsites.txt` foi comentado pois pode ser perigoso remover arquivos automaticamente sem confirmação do usuário
    done
}

GOBUSTER() {
    # Inicializa a array
    ARRAY=()

    # Lê valores do arquivo em uma array
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" != '' ]]; then
            ARRAY+=("$line")
        fi
    done < "$dirlista/$lstsites"

    # Percorre todos os valores da array
    for linha in "${ARRAY[@]}"; do
        mkdir -p "$dir2/$linha/"
        echo -e "\033[32;1m ==== ($lstsites) - GOBUSTER  ==== :=> $linha \033[m"
        echo -e "\033[32;1m Analisando o site ... \033[m"
        
        gobuster dir -u "$linha" -w "$DirAtual/SecLists/Discovery/Web-Content/common.txt" -q -n -e -o "$dir2/$linha/Rel1_$linha"
        gobuster dns -q -n -t 100 -u "$linha" -w "$DirAtual/SecLists/Discovery/DNS/namelist.txt" -o "$dir2/$linha/Rel2_$linha"
        gobuster dns -q -n -u "$linha" -w "$DirAtual/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" -o "$dir2/$linha/Rel3_$linha"
        gobuster dns -q -n -u "$linha" -w "$DirAtual/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" -i -o "$dir2/$linha/Rel4_$linha"
        echo " "
    done
}

HYDRA() {
    dirpass="$DirAtual/SecLists/Usernames/top-usernames-shortlist.txt"
    # Definindo cores
    green="\033[32;1m"
    reset="\033[m"

    # Verificando e lendo valores do arquivo em uma array
    while read -r line; do
        [[ -n "$line" ]] && ARRAY+=("$line")
    done < "$dirlista/$lstsites"

    # Percorrendo todos os valores da array
    for linha in "${ARRAY[@]}"; do
        mkdir -p "$dir2/$linha/"
        echo -e "${green} ==== ($lstsites) - HYDRA  ==== :=> $linha ${reset}"
        echo -e "${green}Analisando o site ... ${reset}"
        
        while read -r user; do
            hydra -l "$user" -P "$DirAtual/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt" "$linha" ftp
            hydra -l "$user" -P "$DirAtual/SecLists/Passwords/Common-Credentials/10k-most-common.txt" "$linha" ssh
        done < "$dirpass"
    done
}

SSLYZE() {
    # Verifica se o diretório existe e lê os valores do arquivo para uma array
    if [ -d "$dirlista" ] && [ -f "$dirlista/$lstsites" ]; then
        mapfile -t ARRAY < <(grep '.' "$dirlista/$lstsites")
    else
        echo "Diretório ou arquivo de lista não encontrado."
        return 1
    fi

    # Verifica se a pasta de destino existe, se não, cria
    [ ! -d "$dir2" ] && mkdir -p "$dir2"

    # Percorre todos os valores da array
    for linha in "${ARRAY[@]}"; do
        mkdir -p "$dir2/$linha/"
        echo -e "\033[32;1m ==== ($lstsites) - sslyze ==== :=> $linha \033[m"
        echo -e "\033[32;1m Analisando o site ... \033[m"
        python -m sslyze "$linha" > "$dir2/$linha/DadosSobreCertf_$linha.html"
    done
}

SCANREDE() {
    echo -e "\033[32;1mIniciando varredura da rede...\033[m"
    # Identificação das interfaces de rede
    NICs=$(ip -br link | awk '{print $1}')
    for i in ${NICs}; do
        # Obtenção do IP, Broadcast e Máscara de Sub-rede
        IP=$(ip addr show $i | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
        BCAST=$(ip addr show $i | grep "brd" | awk '{print $4}')
        MASK=$(ip addr show $i | grep "inet\b" | awk '{print $2}')
        MAC_ADDR=$(ip link show $i | awk '/ether/ {print $2}')
        GW=$(ip route | grep default | grep $i | awk '{print $3}')

        # Se a interface não tiver um endereço IP, pule para a próxima interface
        if [ -z "$IP" ]; then
            continue
        fi

        REDE=$(echo $MASK | cut -d/ -f1)
        dir3="/tmp"
        lstsites="online_ips.txt"
        
        # Escaneamento da rede para portas abertas
        echo "Varrendo a rede $MASK..."
        nmap -p 80 $MASK -oG "$dir3/nullbyte.txt"

        # Filtragem dos IPs online
        grep "Up" "$dir3/nullbyte.txt" | awk '{print $2}' > "$dir3/$lstsites"
        rm -r "$dir3/nullbyte.txt"
        echo -e "\033[32;1m ==== IPs online salvos em $dir3/$lstsites na rede $REDE ==== \033[m"

        # Informações de hardware
        MEM=$(grep "MemTotal" /proc/meminfo | awk '{print $2 $3}')
        NPROC=$(grep -c "processor" /proc/cpuinfo)
        PROC=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[ \t]*//')

        # Exibição das informações coletadas
        echo -e "\033[32;1m ==== Informações de Hardware ==== \033[m"
        echo "Hostname ........: $(hostname)"
        echo "Memória .........: $MEM"
        echo "Processador .....: [ $NPROC ]$PROC"
        echo
        echo -e "\033[32;1m ==== Informações de Rede ==== \033[m"
        echo "Interface .......: $i"
        echo "Endereço IP .....: $IP"
        echo "Endereço Físico .: $MAC_ADDR"
        echo "Broadcast .......: $BCAST"
        echo "Máscara .........: $MASK"
        echo "Rede ............: $REDE"
        echo "Gateway .........: $GW"
        echo "Local de análise : $dir3/$lstsites"
        echo

        DNS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | tr '\n' ' ')
        echo "Servidores DNS ..: $DNS"
        echo
    done
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
