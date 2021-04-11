#! /bin/sh
echo -e $'\e[0;33m[\e[0m\e[1;92m x.. \e[0m\e[0;33m]\e[0m\e[1;92m        Starting installation process     \e[0;33m  [x.. ]\e[0m'  && \
sleep 2  && \
echo -e $'\e[0;33m[\e[0m\e[1;92m xx. \e[0m\e[0;33m]\e[0m\e[1;92m        Starting installation process     \e[0;33m  [xx. ]\e[0m'  && \
sleep 2 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m xxx \e[0m\e[0;33m]\e[0m\e[1;92m        Starting installation process     \e[0;33m  [xxx ]\e[0m'  && \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        UPDATING & UPGRADING LINUX     \e[0;33m  [OK]\e[0m'  && \
sleep 5 && \\
apt update && \\
apt upgrade -yy && \\
sleep 2 && \\
sudo apt-get install tor -y && \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        TOR INSTALLED     \e[0;33m  [OK]\e[0m'  && \
sleep 2  && \
sudo apt-get install wget -y && \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        WGET INSTALLED     \e[0;33m  [OK]\e[0m'  && \
sleep 2  && \
sudo apt-get install make -y&& \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        MAKE INSTALLED    \e[0;33m  [OK]\e[0m'  && \
sleep 2  && \
sudo apt-get install autoconf -y && \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        AUTOCONF INSTALLED     \e[0;33m  [OK]\e[0m'  && \
sleep 2  && \
sudo apt-get install libtool libsodium-dev -y && \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        LIBTOOLS INSTALLED     \e[0;33m  [OK]\e[0m'  && \
sleep 2  && \
sudo apt-get install git -y && \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        GITHUB FETCHER INSTALLED     \e[0;33m  [OK]\e[0m'  && \
sleep 2  && \
sudo apt-get install gcc -y && \
echo -e $'\e[0;33m[\e[0m\e[1;92m STATUS \e[0m\e[0;33m]\e[0m\e[1;92m        COMPILER INSTALLED     \e[0;33m  [OK]\e[0m'  && \
sleep 2  && \
sudo git clone https://github.com/cathugger/mkp224o.git && \
cd mkp224o && \
sudo ./autogen.sh && \
sudo ./configure make && \
sudo make && \
sudo ./mkp224o  -d onions && \
echo -e $'\e[0;33m[\e[0m\e[1;92m Checking \e[0;33m  [.]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m Checking \e[0;33m  [..]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m Checking \e[0;33m  [...]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m Checking \e[0;33m  [....]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m Checking \e[0;33m  [.....]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m  [SUCCESS!]\e[0m \e[0m\e[0;33m]\e[0m\e[1;92m        TO RUN USE ./mkp224o -o onion <PREFIX>    \e[0;33m  [OK]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m  [Building]\e[0m \e[0m\e[0;33m]\e[0m\e[1;92m        V2 ADDRESS GENERATOR DOWNLOADING AND BUILDING    \e[0;33m  [OK]\e[0m' && \
cd && \
git clone https://github.com/ReclaimYourPrivacy/eschalot && \
cd eschalot && \
sudo apt-get install openssl libssl-dev -y && \
make test && \
echo -e $'\e[0;33m[\e[0m\e[1;92m Checking \e[0;33m  [.]\e[0m' && \
sleep 1 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m 	Checking \e[0;33m  [..]\e[0m' && \
sleep 1 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m 		Checking \e[0;33m  [...]\e[0m' && \
sleep 1 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m 	Checking  \e[0;33m  [....]\e[0m' && \
sleep 1 && \
echo -e $'\e[0;33m[\e[0m\e[1;92m Checking \e[0;33m  [.....]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m  [SUCCESS!]\e[0m \e[0m\e[0;33m]\e[0m\e[1;92m        TO RUN USE ./eschalot -p <PREFIX>    \e[0;33m  [OK]\e[0m' && \
sleep 2 && \
echo -e $'\e[0;33m  [COMPLETED]\e[0m \e[0m\e[0;33m]\e[0m\e[1;92m        SCRIPT BY MADHATTER    \e[0;33m  [COMPLETED]\e[0m'
