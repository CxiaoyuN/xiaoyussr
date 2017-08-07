#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
echo
clear
echo

#安装BBR
install_TCP_BBR(){
    clear
	echo
	echo "#############################################################################"
	echo "#                    安装SS-Panel-Mod3环境加速器TCP-BBR                     #"
	echo "# Github: https://github.com/teddysun/across                                #"
	echo "# Author: 小羽                                                              #"
	echo "# QQ群: 600573662                                                           #"
	echo "#############################################################################"
	echo
	wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh
	chmod +x bbr.sh
	./bbr.sh
	echo "################################################################################"
	echo "# SS-Panel-Mod3环境加速器TCP-BBR 安装成功                                      #"
	echo "# 输入 y 并回车后重启,输入以下命令：uname -r验证是否成功安装最新内核。         #"
	echo "# 输入以下命令：lsmod | grep bbr，返回值有 tcp_bbr 模块即说明bbr已启动。       #"
	echo "# Author: 小羽                                                                 #"
	echo "# QQ群: 600573662                                                              #"
	echo "################################################################################"
}
install_TCP_BBR_MOD(){
    clear
	echo
	echo "#############################################################################"
	echo "#                安装SS-Panel-Mod3环境加速器TCP-BBR魔改版                   #"
    echo "#                   仅仅支持Debian8,Debian9,Ubuntu16.04  	                  #"
	echo "# 获取内核版本号：http://kernel.ubuntu.com/~kernel-ppa/mainline/            #"
	echo "#  Ubuntu16.04：推荐4.11.12、4.12.5、或者默认                               #"
	echo "# Github: https://moeclub.org/2017/06/24/278                                #"
	echo "# Author: 小羽                                                              #"
	echo "# QQ群: 600573662                                                           #"
	echo "#############################################################################"
	echo
	wget wget -N --no-check-certificate https://raw.githubusercontent.com/CxiaoyuN/db-ssr/master/bbr.sh
	chmod +x bbr.sh
	bash bbr.sh
	echo "################################################################################"
	echo "# SS-Panel-Mod3环境加速器TCP-BBR魔改版 安装成功                                #"
	echo "# 输入 y 并回车后重启,输入以下命令：uname -r验证是否成功安装最新内核。         #"
	echo "# 输入以下命令：lsmod | grep bbr，返回值有 tcp_bbr 模块即说明bbr已启动。       #"
	echo "# 启动BBR：bash bbr.sh start、关闭BBR：bash bbr.sh stop                        #"
	echo "# 查看BBR状态：bash bbr.sh status、更新：bash bbr.sh                           #"
	echo "# Author: 小羽                                                                 #"
	echo "# QQ群: 600573662                                                              #"
	echo "################################################################################"
}

#Current folder
cur_dir=`pwd`
# Get public IP address
IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
if [[ "$IP" = "" ]]; then
    IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
fi

# Stream Ciphers
ciphers=(
none
aes-256-cfb
aes-192-cfb
aes-128-cfb
aes-256-cfb8
aes-192-cfb8
aes-128-cfb8
aes-256-ctr
aes-192-ctr
aes-128-ctr
chacha20-ietf
chacha20
rc4-md5
rc4-md5-6
)
# Reference URL:
# https://github.com/breakwa11/shadowsocks-rss/blob/master/ssr.md
# https://github.com/breakwa11/shadowsocks-rss/wiki/config.json
# Protocol
protocols=(
origin
verify_deflate
auth_sha1_v4
auth_sha1_v4_compatible
auth_aes128_md5
auth_aes128_sha1
auth_chain_a
auth_chain_b
)
# 混淆方式
obfs=(
plain
http_simple
http_simple_compatible
http_post
http_post_compatible
tls1.2_ticket_auth
tls1.2_ticket_auth_compatible
tls1.2_ticket_fastauth
tls1.2_ticket_fastauth_compatible
)
# Color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# Make sure only root can run our script
rootness(){
    if [[ $EUID -ne 0 ]]; then
       echo "Error: This script must be run as root!" 1>&2
       exit 1
    fi
}

# Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#检测系统
check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif cat /etc/issue | grep -Eqi "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    elif cat /proc/version | grep -Eqi "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ ${checkType} == "sysRelease" ]]; then
        if [ "$value" == "$release" ]; then
            return 0
        else
            return 1
        fi
    elif [[ ${checkType} == "packageManager" ]]; then
        if [ "$value" == "$systemPackage" ]; then
            return 0
        else
            return 1
        fi
    fi
}

# Get version
getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

# CentOS version
centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

# Pre-installation settings
pre_install(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        # Not support CentOS 5
        if centosversion 5; then
            echo "Error: Not supported CentOS 5, please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
            exit 1
        fi
    else
        echo "Error: Your OS is not supported. please change OS to CentOS/Debian/Ubuntu and try again."
        exit 1
    fi
    # Set ShadowsocksR config password
    echo "- - - -- - - - - - - -- - - - - -- - - - - -- - - - - -- - - - - -- "
echo "     欢迎使用小羽一键部署多端口SSR脚本—2017.7.28"
  echo "- - - -- - - - - - - -- - - - - -- - - - - -- - - - - -- - - - - -- "
    echo "设置ShadowsocksR连接密码:"
    read -p "(默认密码是xiaoyu1206):" shadowsockspwd
    [ -z "$shadowsockspwd" ] && shadowsockspwd="xiaoyu1206"
    echo
    echo "---------------------------"
    echo "password = $shadowsockspwd"
    echo "---------------------------"
    echo
    # Set ShadowsocksR config port
    while true
    do
    echo -e "设置第一个远程端口 [1-65535]:"
    read -p "(默认端口: 80):" shadowsocksport
    [ -z "$shadowsocksport" ] && shadowsocksport="80"
    echo -e "设置第二个远程端口 [1-65535]:"
    read -p "(默认端口: 8080):" shadowsocksport2
    [ -z "$shadowsocksport2" ] && shadowsocksport2="8080"
    echo -e "设置第三个远程端口 [1-65535]:"
    read -p "(默认端口: 138):" shadowsocksport3
    [ -z "$shadowsocksport3" ] && shadowsocksport3="138"
    echo -e "设置第四个远程端口 [1-65535]:"
    read -p "(默认端口: 137):" shadowsocksport4
    [ -z "$shadowsocksport4" ] && shadowsocksport4="137"
    echo -e "设置第五个远程端口 [1-65535]:"
    read -p "(默认端口: 53):" shadowsocksport5
    [ -z "$shadowsocksport5" ] && shadowsocksport5="53"    expr ${shadowsocksport} + 0 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ]; then
            echo
            echo "---------------------------"
            echo "port = ${shadowsocksport}"
            echo "---------------------------"
            echo
            break
        else
            echo "Input error, please input correct number"
        fi
    else
        echo "Input error, please input correct number"
    fi
    done
    # 设置 shadowsocksR config 加密方式
    while true
    do
    echo -e "请选择ShadowsocksR 加密方式:"
    for ((i=1;i<=${#ciphers[@]};i++ )); do
        hint="${ciphers[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Which cipher you'd select(默认: ${ciphers[11]}):" pick
    [ -z "$pick" ] && pick=12
    expr ${pick} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Input error, please input a number"
        continue
    fi
    if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
        echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#ciphers[@]}"
        continue
    fi
    shadowsockscipher=${ciphers[$pick-1]}
    echo
    echo "---------------------------"
    echo "加密方式 = ${shadowsockscipher}"
    echo "---------------------------"
    echo
    break
    done

    # 设置 shadowsocksR config 协议
    while true
    do
    echo -e "请选择ShadowsocksR 协议:"
    for ((i=1;i<=${#protocols[@]};i++ )); do
        hint="${protocols[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Which protocol you'd select(默认: ${protocols[3]}):" protocol
    [ -z "$protocol" ] && protocol=4
    expr ${protocol} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Input error, please input a number"
        continue
    fi
    if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
        echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#protocols[@]}"
        continue
    fi
    shadowsockprotocol=${protocols[$protocol-1]}
    echo
    echo "---------------------------"
    echo "协议 = ${shadowsockprotocol}"
    echo "---------------------------"
    echo
    break
    done

    # 设置 shadowsocksR config 混淆方式
    while true
    do
    echo -e "请选择ShadowsocksR 混淆方式:"
    for ((i=1;i<=${#obfs[@]};i++ )); do
        hint="${obfs[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Which obfs you'd select(Default: ${obfs[2]}):" r_obfs
    [ -z "$r_obfs" ] && r_obfs=3
    expr ${r_obfs} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Input error, please input a number"
        continue
    fi
    if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
        echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#obfs[@]}"
        continue
    fi
    shadowsockobfs=${obfs[$r_obfs-1]}
    echo
    echo "---------------------------"
    echo "混淆方式 = ${shadowsockobfs}"
    echo "---------------------------"
    echo
    break
    done
	
    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
    # Install necessary dependencies
    if check_sys packageManager yum; then
        yum install -y unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
    elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install python python-dev python-pip python-m2crypto curl wget unzip gcc swig automake make perl cpio build-essential
    fi
    cd ${cur_dir}
}

# 下载文件
download_files(){
    # Download libsodium file
    if ! wget --no-check-certificate -O libsodium-1.0.13.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.13/libsodium-1.0.13.tar.gz; then
        echo "未能下载 libsodium-1.0.13.tar.gz!"
        exit 1
    fi
    # Download ShadowsocksR file
    if ! wget --no-check-certificate -O manyuser.zip https://github.com/CxiaoyuN/bkw11/archive/manyuser.zip; then
        echo "未能下载 ShadowsocksR 文件!"
        exit 1
    fi
    # Download ShadowsocksR init script
    if check_sys packageManager yum; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/CxiaoyuN/tdys-ss_install/master/shadowsocksR -O /etc/init.d/shadowsocks; then
            echo "未能下载 ShadowsocksR chkconfig文件!"
            exit 1
        fi
    elif check_sys packageManager apt; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/CxiaoyuN/tdys-ss_install/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
            echo "未能下载 ShadowsocksR chkconfig文件!"
            exit 1
        fi
    fi
}

# 防火墙设置
firewall_set(){
    echo "防火墙设置开始..."
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo "port ${shadowsocksport} has been set up."
            fi
        else
            echo "警告:iptables看起来像是关闭或没有安装，请在必要时手动设置它."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo "Firewalld looks like not running, try to start..."
            systemctl start firewalld
            if [ $? -eq 0 ]; then
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
                firewall-cmd --reload
            else
                echo "警告:尝试启动firewalld失败。如有需要，请手动启用$ { shadowsocksport }."
            fi
        fi
    fi
    echo "防火墙设置完成..."
}

# Config ShadowsocksR
config_shadowsocks(){
    cat > /etc/shadowsocks.json<<-EOF
{
 "server": "0.0.0.0",
 "server_ipv6": "::",
 "local_address": "127.0.0.1",
 "local_port":1080,
 "port_password":{
 "${shadowsocksport}":"${shadowsockspwd}",
 "${shadowsocksport2}":"${shadowsockspwd}",
 "${shadowsocksport3}":"${shadowsockspwd}",
 "${shadowsocksport4}":"${shadowsockspwd}",
 "${shadowsocksport5}":"${shadowsockspwd}"
},
 "timeout": 120,
 "udp_timeout": 60,
 "method": "${shadowsockscipher}",
 "protocol": "${shadowsockprotocol}",
 "protocol_param": "",
 "obfs": "${shadowsockobfs}",
 "obfs_param": "",
 "dns_ipv6": true,
 "connect_verbose_info": 0,
 "redirect": "",
 "fast_open": false,
 "workers": 1

}
EOF
}

# 安装 ShadowsocksR
install(){
    # Install libsodium
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        tar zxf libsodium-1.0.13.tar.gz
        cd libsodium-1.0.13
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo "libsodium 安装失败!"
            install_cleanup
            exit 1
        fi
    fi

    ldconfig
    # 安装 ShadowsocksR
    cd ${cur_dir}
	mkdir shadowsocksr-manyuser
    unzip -q manyuser.zip
	cp -r /root/bkw11-manyuser/* /root/shadowsocksr-manyuser/
	rm -rf /root/bkw11-manyuser/
    mv shadowsocksr-manyuser/shadowsocks /usr/local/
    if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x /etc/init.d/shadowsocks
        if check_sys packageManager yum; then
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
        elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks defaults
        fi
        /etc/init.d/shadowsocks start

        clear
        echo
    echo "恭喜你！ ShadowsocksR安装成功！"
        echo -e "服务器 IP: \033[41;37m ${IP} \033[0m"
        echo -e "远程端口: \033[41;37m ${shadowsocksport}、${shadowsocksport2}、${shadowsocksport3}、${shadowsocksport4}、${shadowsocksport5} \033[0m"
        echo -e "连接密码: \033[41;37m ${shadowsockspwd} \033[0m"
        echo -e "本地 IP: \033[41;37m 127.0.0.1 \033[0m"
        echo -e "本地端口: \033[41;37m 1080 \033[0m"
        echo -e "协议: \033[41;37m ${shadowsockprotocol} \033[0m"
        echo -e "混淆方式: \033[41;37m ${shadowsockobfs} \033[0m"
        echo -e "加密方法: \033[41;37m ${shadowsockscipher} \033[0m"
        echo "命令:bash ssr.sh"
        echo "QQ交流群-600573662"       
	    echo "BY 小羽-2017.7.28"
    else
        echo "你丑，ShadowsocksR 安装失败！"
        install_cleanup
        exit 1
    fi
}

# 安装 cleanup
install_cleanup(){
    cd ${cur_dir}
    rm -rf manyuser.zip shadowsocksr-manyuser libsodium-1.0.13.tar.gz libsodium-1.0.13
}


# 卸载 ShadowsocksR
uninstall_shadowsocks(){
    printf "是否卸载ShadowsocksR? (y/n)"
    printf "\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        /etc/init.d/shadowsocks status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        if check_sys packageManager yum; then
            chkconfig --del shadowsocks
        elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks remove
        fi
        rm -f /etc/shadowsocks.json
        rm -f /etc/init.d/shadowsocks
        rm -f /var/log/shadowsocks.log
        rm -rf /usr/local/shadowsocks
        echo "ShadowsocksR 卸载成功!"
    else
        echo
        echo "uninstall cancelled, nothing to do..."
        echo
    fi
}

# 安装 ShadowsocksR
install_shadowsocks(){
    rootness
    disable_selinux
    pre_install
    download_files
    config_shadowsocks
    install
    if check_sys packageManager yum; then
        firewall_set
    fi
    install_cleanup
}

# Initialization step
echo -e "\033[36m############################################################################\033[0m"
echo -e "\033[36m#                       小羽一键部署多端口SSR脚本                          #\033[0m"
echo -e "\033[36m#                   2017年7月28日更新：添加BBR加速器                       #\033[0m"
echo -e "\033[36m# Author: 小羽                                                             #\033[0m"
echo -e "\033[36m# QQ群: 600573662                                                          #\033[0m"
echo -e "\033[36m# 请选择你要安装的脚本                                                     #\033[0m"
echo -e "\033[36m# 1  安装 ShadowsocksR                                                     #\033[0m"
echo -e "\033[36m# 2  安装 BBR 加速器（魔版）                                               #\033[0m"
echo -e "\033[36m# 3  安装 BBR 加速器（原版）                                               #\033[0m"
echo -e "\033[36m# x  卸载 ShadowsocksR                                                     #\033[0m"
echo -e "\033[36m############################################################################\033[0m"
echo
stty erase '^H' && read -p " 请输入数字 [1-x]:" num
case "$num" in
	1)
	install_shadowsocks
	;;
	2)
	install_TCP_BBR_MOD
	;;
	3)
	install_TCP_BBR
	;;
	x)
	uninstall_shadowsocks
	;;
	*)
	echo "请输入正确数字 [1-x]"
	;;
esac
