```bash
alias ifconfig='sudo ifconfig'
alias s='sudo'
alias c='clear'
alias ..='cd ..'
alias ...='cd ../../'
alias ....='cd ../../../'
alias .....='cd ../../../../'
alias l='ls -lart --block-size=M'
alias h='history'
alias autoremove='sudo apt-get autoremove -y'
alias autoclean='sudo apt-get autoclean -y'
alias root='sudo -i'
alias diff='colordiff'
alias qvenv='python3 -m venv venv && source venv/bin/activate'
alias webup='sudo python -m http.server 80'
alias httpup='sudo ~/apps/up-http-tool/up'
alias ftpup='sudo python -m pyftpdlib -p 21'
alias smbup='sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support share $(pwd)'
alias vpn-htb='sudo openvpn --config /home/crystal/Documents/HTB.ovpn'
alias vpn-academy='sudo openvpn --config /home/crystal/Documents/HTB-Academy.ovpn'
alias vpn-release_arena='sudo openvpn --config /home/crystal/Documents/HTB-Release-Arena.ovpn'
alias vpn-starting_point='sudo openvpn --config /home/crystal/Documents/HTB-Starting-Point.ovpn'
alias vpn-thm='sudo openvpn --data-ciphers "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC" --config /home/crystal/Documents/THM.ovpn'
alias nse='ls /usr/share/nmap/scripts | grep'
alias nse-help='nmap --script-help'
alias nasm_shell='/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb'
alias msfelfscan='/usr/share/framework2/msfelfscan'
alias aslr_off='echo 0 | sudo tee /proc/sys/kernel/randomize_va_space'
alias gcc_no_protections='gcc -fno-stack-protector -z execstack -no-pie'
alias dvwa_start='sudo service mysql start && sudo service apache2 start'
alias docker_fix='sudo mkdir /sys/fs/cgroup/systemd; sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd'
alias pipz_upgrade='pip freeze > requirements.txt; pip install -r requirements.txt --break --upgrade; rm requirements.txt;'
alias gemz_upgrade='sudo gem update; sudo gem clean'
alias username-anarchy='ruby /home/crystal/apps/username-anarchy/username-anarchy'
alias jwt_tool='python /home/crystal/apps/jwt_tool/jwt_tool.py'
alias wes-ng='python /home/crystal/Desktop/scripts/windows/wesng/wes.py'
alias android_studio='/home/crystal/apps/android-studio/bin/studio.sh'
alias ghidra_auto='python3 /home/crystal/apps/auto_ghidra.py'
alias ctfd_download='python ~/ctf/helpers/ctfd_download_python/download.py'
alias enum4linux='python /home/crystal/Desktop/scripts/enum4linux-ng/enum4linux-ng.py'
alias subbrute='python /home/crystal/apps/subbrute/subbrute.py'
alias codemerx='/home/crystal/apps/codemerx/bin/CodemerxDecompile'
alias xs-strike='python /home/crystal/apps/XSStrike/xsstrike.py'
alias eyewitness='python /home/crystal/apps/EyeWitness/Python/EyeWitness.py'
alias wordlist_dl='sudo python /home/crystal/apps/wordlistctl/wordlistctl.py'
alias tplmap='python /home/crystal/apps/tplmap/tplmap.py'

installz(){ sudo apt-get install -y "$1"; }
pipz(){ pip install "$1" --break-system-packages; }

ss(){ searchsploit "$@"; }
ssx(){ searchsploit -x "$1"; }
ssm(){ searchsploit -m "$1"; }

gobusterz(){ gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u "$1"; }
mscanz(){ sudo masscan -p1-65535,U:1-65535 "$1" --rate=1000 -e tun0 --wait 5 > mscan.txt; }
qmapz(){ sudo nmap -sV -sC "$1"; }

pattern_create(){ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l "$1"; }
pattern_offset(){ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q "$1"; }

mount(){
  if [ $# -eq 0 ]; then command mount | column -t; else sudo mount "$@"; fi
}

wpscanz(){ wpscan -e ap,t,u --api-token REDACTED --url "$1"; }
wpbrute(){ wpscan --password-attack xmlrpc -U "$2" -P "$3" --api-token REDACTED --url "$1"; }

mobsf_emulator(){ emulator -avd "$1" -writable-system -no-snapshot; }
webdavup(){ sudo wsgidav --host="$1" --port="$2" --root=/tmp --auth=anonymous; }

pchainz(){ proxychains4 -q bash; }
urlencode(){ python3 -c "from pwn import *; print(urlencode('$1'))"; }
urldecode(){ python3 -c "from pwn import *; print(urldecode('$1'))"; }

ffuf-vhost(){ arg_count=3; if [[ $2 && $2 != -* ]]; then wordlist=$2; else wordlist='/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'; arg_count=2; fi; ffuf -c -H "Host: FUZZ.$1" -u http://$1 -w $wordlist ${@: $arg_count}; }
ffuf-dir(){ arg_count=3; if [[ $2 && $2 != -* ]]; then wordlist=$2; else wordlist='/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt'; arg_count=2; fi; ffuf -c -u $1FUZZ -w $wordlist ${@: $arg_count}; }
ffuf-req(){ arg_count=2; if [[ $1 && $1 != -* ]]; then wordlist=$1; else wordlist='/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt'; arg_count=1; fi; ffuf -c -ic -request new.req -request-proto https -w $wordlist ${@: $arg_count}; }

plzsh(){ if [[ $1 ]]; then port=$1; else port=1337; fi; stty raw -echo; (echo 'python3 -c "import pty;pty.spawn(\"/bin/bash\")" || python -c "import pty;pty.spawn(\"/bin/bash\")"' ;echo "stty$(stty -a | awk -F ';' '{print $2 $3}' | head -n 1)"; echo reset;cat) | nc -lvnp $port && reset; }
qssh(){ sshpass -p "$2" ssh -o StrictHostKeyChecking=no "$1"@"$3" ${@: 4}; }
rdp(){ xfreerdp /u:"$1" /p:"$2" /v:"$3" /size:1440x810 /clipboard /cert-ignore ${@: 4}; }

extract(){ if [ -z "$1" ]; then echo "Usage: extract <file>"; elif [ -f "$1" ]; then case "$1" in *.tar.bz2) tar xvjf "$1";; *.tar.gz) tar xvzf "$1";; *.tar.xz) tar xvJf "$1";; *.lzma) unlzma "$1";; *.bz2) bunzip2 "$1";; *.rar) unrar x -ad "$1";; *.gz) gunzip "$1";; *.tar) tar xvf "$1";; *.tbz2) tar xvjf "$1";; *.tgz) tar xvzf "$1";; *.zip) unzip "$1";; *.Z) uncompress "$1";; *.7z) 7z x "$1";; *.xz) unxz "$1";; *.exe) cabextract "$1";; *) echo "extract: '$1' - unknown archive method";; esac; else echo "$1 - file does not exist"; fi; }
lowercase_extensions(){ for file in *.*; do ext="${file##*.}"; lower_ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]'); if [[ "$ext" != "$lower_ext" ]]; then mv "$file" "${file%.*}.$lower_ext"; fi; done; }

docker_run(){ docker build -t temp-app:latest . && if [ -n "$1" ]; then docker run --rm -it -p "$1":1337 temp-app:latest; else docker run --rm -it temp-app:latest; fi; }
```