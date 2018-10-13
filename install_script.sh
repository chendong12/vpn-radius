#!/bin/bash
#
function set_ntp(){
	setenforce 0
	sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
	yum -y install ntp
	service ntpd restart
	cp -rf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	cd /root
	echo '0-59/10 * * * * /usr/sbin/ntpdate -u cn.pool.ntp.org' >> /tmp/crontab.back
	crontab /tmp/crontab.back
	systemctl restart crond
}
#获取公网ip，设置共享密钥
function set_shell_input1() {
	clear	
	sqladmin=0p0o0i0900
	yum install lynx -y
	public_ip=`lynx --source www.monip.org | sed -nre 's/^.* (([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'`
	ike_passwd=fastvpn
yum install network-tools -y
}
function set_install_pro2(){
	#解决ssh访问慢的问题,可以安装完脚本后手工重启ssh
	sed -i "s/GSSAPIAuthentication yes/GSSAPIAuthentication no/g" /etc/ssh/sshd_config
	alias cp='cp'
	yum groupinstall "Development tools" -y
	yum install wget vim expect telnet net-tools httpd mariadb-server php php-mysql php-gd php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap curl curl-devel -y
	yum install freeradius freeradius-mysql freeradius-utils -y
	systemctl restart mariadb
	systemctl restart httpd
	systemctl stop firewalld
	systemctl disable firewalld
}
#配置radius数据库并导入数据
function set_mysql3() {
	systemctl restart mariadb
	sleep 3
	mysqladmin -u root password ""${sqladmin}""
	mysql -uroot -p${sqladmin} -e "create database radius;"
	mysql -uroot -p${sqladmin} -e "grant all privileges on radius.* to radius@localhost identified by 'p0radius_0p';"
	mysql -uradius -p'p0radius_0p' radius < /etc/raddb/mods-config/sql/main/mysql/schema.sql  
	systemctl restart mariadb
}

function set_freeradius4(){
	ln -s /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/
	sed -i "s/auth = no/auth = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/auth_badpass = no/auth_badpass = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/auth_goodpass = no/auth_goodpass = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/\-sql/sql/g" /etc/raddb/sites-available/default
	#在查找到的session {字符串后面插入内容
	sed -i '/session {/a\        sql' /etc/raddb/sites-available/default
	sed -i 's/driver = "rlm_sql_null"/driver = "rlm_sql_mysql"/g' /etc/raddb/mods-available/sql	
	#查找到字符串，去掉首字母为的注释#
	sed -i '/read_clients = yes/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/dialect = "sqlite"/s/^#//' /etc/raddb/mods-available/sql
	sed -i 's/dialect = "sqlite"/dialect = "mysql"/g' /etc/raddb/mods-available/sql	
	sed -i '/server = "localhost"/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/port = 3306/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/login = "radius"/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/password = "radpass"/s/^#//' /etc/raddb/mods-available/sql
	sed -i 's/password = "radpass"/password = "p0radius_0p"/g' /etc/raddb/mods-available/sql	
	systemctl restart radiusd
	sleep 3
}
function set_daloradius5(){
	cd /var/www/html/
	wget http://180.188.197.212/down/daloradius-0.9-9.tar.gz >/dev/null 2>&1
	tar xzvf daloradius-0.9-9.tar.gz
	mv daloradius-0.9-9 daloradius
	chown -R apache:apache /var/www/html/daloradius/
	chmod 664 /var/www/html/daloradius/library/daloradius.conf.php
	cd /var/www/html/daloradius/
	mysql -uradius -p'p0radius_0p' radius < contrib/db/fr2-mysql-daloradius-and-freeradius.sql
	mysql -uradius -p'p0radius_0p' radius < contrib/db/mysql-daloradius.sql
	sleep 3
	sed -i "s/\['CONFIG_DB_USER'\] = 'root'/\['CONFIG_DB_USER'\] = 'radius'/g"  /var/www/html/daloradius/library/daloradius.conf.php
	sed -i "s/\['CONFIG_DB_PASS'\] = ''/\['CONFIG_DB_PASS'\] = 'p0radius_0p'/g" /var/www/html/daloradius/library/daloradius.conf.php
	yum -y install epel-release
	yum -y install php-pear-DB
	systemctl restart mariadb.service 
	systemctl restart radiusd.service
	systemctl restart httpd
	chmod 644 /var/log/messages
	chmod 755 /var/log/radius/
	chmod 644 /var/log/radius/radius.log
	touch /tmp/daloradius.log
	chmod 644 /tmp/daloradius.log
	chown -R apache:apache /tmp/daloradius.log
}

function set_strongswan6(){
    yum -y install strongswan strongswan-tnc-imcvs strongswan-libipsec
	cd /root/
	touch zhengshu.sh 
cat >> /root/zhengshu.sh <<EOF
#!/bin/bash
strongswan pki --gen --outform pem > ca.key.pem
strongswan pki --self --in ca.key.pem --dn "C=CN, O=Fastvpn, CN=Fastvpn CA" --ca --lifetime 3650 --outform pem > ca.cert.pem
strongswan pki --gen --outform pem > server.key.pem
strongswan pki --pub --in server.key.pem --outform pem > server.pub.pem
strongswan pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in server.pub.pem --dn "C=CN, O=Fastvpn, CN=$public_ip" --san="$public_ip" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem
strongswan pki --gen --outform pem > client.key.pem
strongswan pki --pub --in client.key.pem --outform pem > client.pub.pem
strongswan pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in client.pub.pem --dn "C=CN, O=Fastvpn, CN=$public_ip" --outform pem > client.cert.pem
openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "Fastvpn Client Cert" -certfile ca.cert.pem -caname "Fastvpn CA" -out client.cert.p12 -password pass:
cp -r ca.key.pem /etc/strongswan/ipsec.d/private/
cp -r ca.cert.pem /etc/strongswan/ipsec.d/cacerts/
cp -r server.cert.pem /etc/strongswan/ipsec.d/certs/
cp -r server.key.pem /etc/strongswan/ipsec.d/private/
cp -r client.cert.pem /etc/strongswan/ipsec.d/certs/
cp -r client.key.pem /etc/strongswan/ipsec.d/private/
cat ca.cert.pem >> /etc/raddb/certs/ca.pem
cat server.cert.pem >> /etc/raddb/certs/server.pem
cat server.key.pem >> /etc/raddb/certs/server.key
cat /etc/raddb/certs/server.key >> /etc/raddb/certs/server.pem
EOF
chmod +x /root/zhengshu.sh
echo '' > /etc/strongswan/ipsec.conf
cat >>  /etc/strongswan/ipsec.conf <<EOF
config setup
    uniqueids=never          
conn %default
     keyexchange=ike              #ikev1 或 ikev2 都用这个
     ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
     esp=aes256-sha256,aes256-sha1,3des-sha1!
     auto=start
     closeaction = clear
     dpddelay = 60s        #每60秒向客户发送数据包以检测用户是否在线，不在线则断开！
     dpdtimeout = 120s   #120秒内没收到用户发回的数据包则强制断开！ 
     inactivity = 30m  #30分钟内用户与服务器没有数据交互则强制断开！
     ikelifetime = 8h   #每次连接的最长有效期，超过有效期则自动重新连接
     keyingtries = 3   #连接最大尝试数
     lifetime=1h
     margintime = 5m   #ikelifetime 超时前5分钟重新协商连接，以免被强制断开！
     dpdaction = clear   #清除不响应用户的所有缓存、安全信息，Dead Peer Detection
     left=%any                    #服务器端标识,%any表示任意
     leftsubnet=0.0.0.0/0         #服务器端虚拟ip, 0.0.0.0/0表示通配.
     right=%any                   #客户端标识,%any表示任意
conn IKE-BASE
    leftca=ca.cert.pem           #服务器端 CA 证书
    leftcert=server.cert.pem     #服务器端证书
    rightsourceip=10.0.0.0/24    #分配给客户端的虚拟 ip 段，格式为：单个IP或1.1.1.1-1.1.1.5或1.1.1.0/24
 
#供 ios 使用, 使用客户端证书
conn IPSec-IKEv1
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes         #开启对 iOS 拆包的重组支持
    leftauth=pubkey
    rightauth=pubkey
    rightauth2=xauth-radius  #使用radius
    rightcert=client.cert.pem
    auto=add
 
#供 ios 使用, 使用 PSK 预设密钥
conn IPSec-IKEv1-PSK
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes
    leftauth=psk
    rightauth=psk
    rightauth2=xauth-radius #使用radius
    auto=add
 
#供 使用ikev2 协议连接使用（osx、windows、ios）
conn IPSec-IKEv2
    keyexchange=ikev2
    ike=aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024!
    esp=aes256-sha256,3des-sha1,aes256-sha1!
    rekey=no
    left=%defaultroute
    leftid=$public_ip
    leftsendcert=always
    leftfirewall=yes
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-radius
    rightsourceip=10.0.0.150-10.0.0.254
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
    auto=add
 
#供 windows 7+ 使用, win7 以下版本需使用第三方 ipsec vpn 客户端连接
conn IPSec-IKEv2-EAP
    also=IKE-BASE
    keyexchange=ikev2
    #ike=aes256-sha1-modp1024!   #第一阶段加密方式
    rekey=no                     #服务器对 Windows 发出 rekey 请求会断开连接
    leftauth=pubkey
    rightauth=eap-radius
    rightsendcert=never          #服务器不要向客户端请求证书
    eap_identity=%any
    auto=add
#供linux客户端
conn ipke2vpn
    keyexchange=ikev2
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,3des-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%defaultroute
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    leftid=$public_ip
    right=%any
    rightsourceip=10.0.0.0/24
    authby=secret
    rightsendcert=never
    eap_identity=%any
    auto=add
EOF
echo '' > /etc/strongswan/strongswan.conf
cat >>  /etc/strongswan/strongswan.conf <<EOF
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details
#
# Configuration changes should be made in the included files
charon {
        i_dont_care_about_security_and_use_aggressive_mode_psk = yes
        duplicheck.enable = no
        threads = 16
        compress = yes 
        load_modular = yes
        plugins {
                include strongswan.d/charon/*.conf    
               }
	dns1 = 8.8.8.8
	dns2 = 114.114.114.114
}
include strongswan.d/*.conf
EOF
sed -i "s/# accounting = no/accounting = yes/g" /etc/strongswan/strongswan.d/charon/eap-radius.conf 
#\n是回车 \t tab
sed -i '/servers {/a\ \t radius{\n \t address = 127.0.0.1 \n \t secret = testing123 \n \t \t }' /etc/strongswan/strongswan.d/charon/eap-radius.conf 
sed -i "s/# backend = radius/ backend = radius/g" /etc/strongswan/strongswan.d/charon/xauth-eap.conf
cat >>  /etc/strongswan/ipsec.secrets <<EOF
: RSA server.key.pem #使用证书验证时的服务器端私钥
: PSK $ike_passwd #使用预设密钥时, 8-63位ASCII字符
: XAUTH $ike_passwd
EOF
chmod o+r /etc/strongswan/ipsec.secrets
chmod o+x /etc/strongswan/
}

function set_fix_radacct_table7(){
	cd /tmp
	sleep 3
	wget http://180.188.197.212/down/radacct_new.sql.tar.gz
	tar xzvf radacct_new.sql.tar.gz
	mysql -uradius -p'p0radius_0p' radius < /tmp/radacct_new.sql
	rm -rf radacct_new.sql.tar.gz
	rm -rf radacct_new.sql
	systemctl restart strongswan
	systemctl restart radiusd

}

function set_openvpn8(){
	modprobe tun
	yum -y install openssl openssl-devel lzo openvpn easy-rsa
	yum -y install expect
cp -rf /usr/share/easy-rsa/ /etc/openvpn
cd /etc/openvpn/easy-rsa/3.0
./easyrsa init-pki 
expect<<-END
spawn ./easyrsa build-ca nopass
expect "CA]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa gen-req server nopass
expect "server]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa sign server server
expect "details:"
send "yes\r"
expect eof
exit
END
./easyrsa gen-dh 
touch /etc/openvpn/server.conf
cat >>  /etc/openvpn/server.conf <<EOF
port 1194 # default port
proto udp # default protocol
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
reneg-sec 0
ca /etc/openvpn/easy-rsa/3.0/pki/ca.crt
cert /etc/openvpn/easy-rsa/3.0/pki/issued/server.crt
key /etc/openvpn/easy-rsa/3.0/pki/private/server.key
dh /etc/openvpn/easy-rsa/3.0/pki/dh.pem
#plugin /usr/share/openvpn/plugin/lib/openvpn-auth-pam.so /etc/pam.d/login # 如果使用freeradius，请注释这一行
plugin /etc/openvpn/radiusplugin.so /etc/openvpn/radiusplugin.cnf # 如果使用freeradius，请去掉这一行的注释
server 10.8.0.0 255.255.255.0 # 分配给VPN客户端的地址范围
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "route 192.168.0.0 255.255.255.0"    #指定VPN客户端访问你服务器的内网网段
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 2 20
comp-lzo
persist-key
persist-tun
status openvpn-status.log
log-append openvpn.log
verb 3
#script-security 3
#auth-user-pass-verify /etc/openvpn/checkpsw.sh via-env
client-cert-not-required            #启用后，就关闭证书认证，只通过账号密码认证
username-as-common-name
EOF
touch /etc/openvpn/easy-rsa/3.0/client.ovpn
cat >>  /etc/openvpn/easy-rsa/3.0/client.ovpn <<EOF
client
dev tun
proto udp
remote $public_ip 1194 # – Your server IP and OpenVPN Port
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
ca ca.crt
auth-user-pass
comp-lzo
reneg-sec 0
verb 3
EOF
}
function set_openvpn_freeradius9(){
	yum -y install libgcrypt libgcrypt-devel gcc-c++
	cd /tmp
	wget http://180.188.197.212/down/radiusplugin_v2.1a_beta1.tar.gz
	tar xzvf radiusplugin_v2.1a_beta1.tar.gz
	rm -rf radiusplugin_v2.1a_beta1.tar.gz
	cd radiusplugin_v2.1a_beta1
	make
	cp -rf radiusplugin.so /etc/openvpn/
	cp -rf radiusplugin.cnf /etc/openvpn/
	sed -i "s/name=192.168.0.153/name=127.0.0.1/g" /etc/openvpn/radiusplugin.cnf
	sed -i "s/sharedsecret=testpw/sharedsecret=testing123/g" /etc/openvpn/radiusplugin.cnf
	systemctl restart openvpn@server
}
function set_iptables10(){
	echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
	sysctl -p
	yum -y install iptables-services
	systemctl start iptables.service
	chmod +x /etc/rc.local
netcard_name=`ifconfig | head -1 | awk -F ":" '{print$1}'`	
cat >>  /etc/rc.local <<EOF
systemctl start mariadb
systemctl start httpd
systemctl start radiusd
systemctl start strongswan
systemctl start iptables
systemctl start openvpn@server
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
iptables -A INPUT -p tcp --dport 9091 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT 
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p gre -j ACCEPT
iptables -A INPUT -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -i ppp+ -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d 10.0.0.0/24 -j ACCEPT
iptables -A FORWARD -s 10.0.0.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $netcard_name -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $netcard_name -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o $netcard_name -j MASQUERADE
EOF
}

function set_web_config(){
echo  "
Listen 9090
Listen 9091
<VirtualHost *:9090>
 DocumentRoot "/var/www/html/daloradius"
 ServerName daloradius
 ErrorLog "logs/daloradius-error.log"
 CustomLog "logs/daloradius-access.log" common
</VirtualHost>
<VirtualHost *:9091>
 DocumentRoot "/var/www/html/user_reg_new"
 ServerName userReg
 ErrorLog "logs/test-error.log"
 CustomLog "logs/test-access.log" common
</VirtualHost>
" >> /etc/httpd/conf/httpd.conf
cd /var/www/html/
rm -rf *
wget http://180.188.197.212/down/daloradius20180418.tar.gz 
tar xzvf daloradius20180418.tar.gz 
rm -rf daloradius20180418.tar.gz
wget http://180.188.197.212/down/user_reg_new20180418.tar.gz
tar xzvf user_reg_new20180418.tar.gz
rm -rf user_reg_new20180418.tar.gz
chown -R apache:apache /var/www/html/daloradius
chown -R apache:apache /var/www/html/user_reg_new
service httpd restart
mkdir /usr/mysys/
cd /usr/mysys/
wget http://180.188.197.212/down/dbback.tar.gz
tar xzvf dbback.tar.gz
rm -rf dbback.tar.gz
echo 'mysql -uradius -pp0radius_0p -e "UPDATE radius.radacct SET acctstoptime = acctstarttime + acctsessiontime WHERE ((UNIX_TIMESTAMP(acctstarttime) + acctsessiontime + 240 - UNIX_TIMESTAMP())<0) AND acctstoptime IS NULL;"' >> /usr/mysys/clearsession.sh
chmod +x /usr/mysys/clearsession.sh
echo '0-59/10 * * * * /usr/mysys/clearsession.sh' >> /tmp/crontab.back
echo '0 0 1 * * /usr/mysys/dbback/backup_radius_db.sh' >> /tmp/crontab.back
crontab /tmp/crontab.back
systemctl restart crond
}

function set_initvpn(){
netcard_name=`ifconfig | head -1 | awk -F ":" '{print$1}'`
#调整公网IP地址
newPubIP=`lynx --source www.monip.org | sed -nre 's/^.* (([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'`
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i /var/www/html/user_reg_new/class.user.php
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i  /var/www/html/daloradius/library/exten-welcome_page.php
    sed -r 's/leftid=\"(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/leftid=\"$newPubIP/g -i /etc/strongswan/ipsec.conf
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i  /etc/openvpn/easy-rsa/3.0/client.ovpn
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i /root/zhengshu.sh
cd /root/
./zhengshu.sh
zip -p -r client.zip client.cert.p12
zip -p -r ca.zip ca.cert.pem
alias cp='cp'
cp -rf client.zip /var/www/html/user_reg_new/
cp -rf ca.zip /var/www/html/user_reg_new/
mkdir openvpnclient
cp -rf /etc/openvpn/easy-rsa/3.0/client.ovpn ./openvpnclient/
cp -rf /etc/openvpn/easy-rsa/3.0/pki/ca.crt ./openvpnclient/
zip -p -r openvpnclient.zip ./openvpnclient/
cp -rf openvpnclient.zip /var/www/html/user_reg_new/
service strongswan restart
cd /root/
wget http://180.188.197.212/down/initvpn20180418.zip
unzip initvpn20180418.zip
rm -rf initvpn20180418.zip
/etc/rc.local
echo "==========================================================================
                  Centos7 VPN 安装完成                            
										 
				  以下信息将自动保存到/root/info.txt文件中			
                                                                         
                   openvpn 需要导出的客户端配置文件/etc/openvpn/easy-rsa/3.0/client.ovpn 

                   openvpn 需要导出客户端证书文件 /etc/openvpn/easy-rsa/3.0/pki/ca.crt 

                   openvpn 服务器配置文件/etc/openvpn/server.conf 

                   strongswan VPN 预共享密钥:$ike_passwd 

                   strongswan 证书生成文件/root/zhengshu.sh 

                   strongswan 服务器配置文件/etc/strongswan/ipsec.conf 

                   strongSwan 共享密钥配置文件 /etc/strongswan/ipsec.secrets 

                   strongSwan 客户端DNS配置文件 /etc/strongswan/strongswan.conf

                   strongswan 连接radius密钥配置文件/etc/strongswan/strongswan.d/charon/eap-radius.conf

                   开机启动配置文件/etc/rc.local  

                   mysql root用户密码:0p0o0i0900      

		          用户注册后台登录地址:http://$newPubIP:9091

		          VPN 账号管理后台地址：http://$newPubIP:9090
		                             账号：administrator 密码:radius

==========================================================================" > /root/info.txt
	sleep 3
	cat /root/info.txt
	exit;
}

function shell_install() {
	echo '初始化设置，请按照下面提示设置您的密码等配置'
	set_shell_input1
	echo "初始化时间"
	set_ntp
	echo '安装freeradius、mariadb、php'
	set_install_pro2
	sleep 3
	echo '开始配置数据库'
	set_mysql3
	echo '配置freeradius'
	set_freeradius4
	echo '安装配置daloradius'
	set_daloradius5
	echo '安装配置strongswan'
	set_strongswan6
	echo '修复radacct表'
	set_fix_radacct_table7
	echo '安装配置openvpn'
	set_openvpn8
	echo '配置openvpn与freeradius连动'
	set_openvpn_freeradius9
	echo '配置iptables'
	set_iptables10
	echo '配置daloradius'
	set_web_config
	echo 'vpn服务器初始化IP'
	set_initvpn
}
shell_install

