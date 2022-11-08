```sh
alias ifconfig='sudo ifconfig'
alias s='sudo'
alias c='clear'
alias ..='cd ..'
alias ...='cd ../../'
alias ....='cd ../../../'
alias .....='cd ../../../../'
alias l='ls -lart'
alias h='history'
alias installz='sudo apt-get install $1 -y'
alias autoremove='sudo apt-get autoremove -y'
alias autoclean='sudo apt-get autoclean -y'
alias root='sudo -i'
alias diff='colordiff'
alias mount='sudo mount | column -t'
alias webup='sudo python -m http.server 80'
alias httpup='sudo ~/apps/up-http-tool/up'
alias ftpup='sudo python -m pyftpdlib -p 21'
alias smbup='sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support share $(pwd)'
alias vpn-htb='sudo openvpn --config /home/crystal/HTB.ovpn'
alias vpn-academy='sudo openvpn --config /home/crystal/HTB-Academy.ovpn'
alias vpn-release_arena='sudo openvpn --config /home/crystal/HTB-Release-Arena.ovpn'
alias vpn-starting_point='sudo openvpn --config /home/crystal/HTB-Starting-Point.ovpn'
alias vpn-thm='sudo openvpn --config /home/crystal/THM.ovpn'
alias ss='searchsploit $1'
alias ssx='searchsploit -x $1'
alias ssm='searchsploit -m $1'
alias gobusterz='gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u $1'
alias mscanz='sudo masscan -p1-65535,U:1-65535 $1 --rate=1000 -e tun0 --wait 5 > mscan.txt'
alias nmapz='/home/crystal/scripts/gen_nmap.py; while read item; do sudo nmap -sV -sC -sU -sS $item; done < nmap.txt; rm mscan.txt nmap.txt'
alias qmapz='sudo nmap -sV -sC $1'
alias nse='ls /usr/share/nmap/scripts | grep'
alias nse-help='nmap --script-help'
alias pattern_create='/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l $1'
alias pattern_offset='/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q $1' 
alias nasm_shell='/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb'
alias msfelfscan='/usr/share/framework2/msfelfscan'
alias wpscan='wpscan -e ap,t,u --api-token <no_stealing_cats_tokens> --url $1'
alias aslr_off='echo 0 | sudo tee /proc/sys/kernel/randomize_va_space'
alias gcc_no_protections='gcc -fno-stack-protector -z execstack -no-pie'
alias dvwa_start='sudo service mysql start && sudo service apache2 start'
alias docker_fix='sudo mkdir /sys/fs/cgroup/systemd; sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd'
alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:1.10.0'
alias pipz_upgrade='pip freeze > requirements.txt; pip install -r requirements.txt --upgrade; rm requirements.txt;'
alias pwninit='/home/crystal/apps/pwninit --template-path ~/.config/pwninit-template.py; sed -n "4,6p" solve.py; rm solve.py; mv *_patched $1'
alias burpsuite='java -jar --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED /usr/bin/burpsuite'
alias mobsf_emulator='emulator -avd $1 -writable-system -no-snapshot'
alias webdavup='sudo wsgidav --host=$1 --port=$2 --root=/tmp --auth=anonymous'
urlencode() {
    python3 -c "from pwn import *; print(urlencode('$1'));"
}
urldecode() {
    python3 -c "from pwn import *; print(urldecode('$1'));"
}
ffuf-vhost() {
    arg_count=3
    if [[ $2 && $2 != -* ]]; then
        wordlist=$2
    else
        wordlist='/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'
        arg_count=2
    fi
    ffuf -c -H "Host: FUZZ.$1" -u http://$1 -w $wordlist ${@: $arg_count};
}
ffuf-dir() {
    arg_count=3
    if [[ $2 && $2 != -* ]]; then
        wordlist=$2
    else
        wordlist='/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt'
        arg_count=2
    fi
    ffuf -c -u $1FUZZ -w $wordlist ${@: $arg_count};
}
ffuf-req() {
    arg_count=2
    if [[ $1 && $1 != -* ]]; then
        wordlist=$1
    else
        wordlist='/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt'
        arg_count=1
    fi
    ffuf -c -ic -request new.req -request-proto http -w $wordlist ${@: $arg_count};
}
plzsh() {
    if [[ $1 ]]; then
        port=$1
    else
        port=1337
    fi
    stty raw -echo; (echo 'python3 -c "import pty;pty.spawn(\"/bin/bash\")" || python -c "import pty;pty.spawn(\"/bin/bash\")"' ;echo "stty$(stty -a | awk -F ';' '{print $2 $3}' | head -n 1)"; echo reset;cat) | nc -lvnp $port && reset
}
qssh() {
    sshpass -p $2 ssh -o StrictHostKeyChecking=no $1@$3 ${@: 4};
}
rdp() {
    xfreerdp /u:$1 /p:$2 /v:$3 /size:1440x810 /clipboard /cert-ignore ${@: 4};
}
```
