#!/bin/bash -e
# author: g-glory-n
# date: 2020.6.25


if [ "$0" != "./run_demo.sh" ] && [ "$0" != "bash ./run_demo.sh" ]
then
	printf "\n"
	echo -e " please into source directory to execute \"./run_demo.sh\" or \"bash ./run_demo.sh\"!"
	printf "\n"
	exit 1
fi


whiptail --title "welcome" --msgbox "               description: libpcap demo\n\n                   author: g-glory-n\n                   date: 2020.06.25\n" 10 60

# check if user is root
# [ $(id -u) != "0" ] && { echo -e "\033[31merror: you must be root to run this script\033[0m"; exit 1; }


# This script is used to get root permission
set -e # effect: cancel button can be pushed out normally when using whiptail!
if [ "$(whoami)" == "root" ] # determine whether user is root
then
    echo ""
    echo -e "\033[31m\tyou have get root permission!\033[0m"
    echo ""
else
    for ((i = 0; i < 4; i++)) # get root permission
    do
        if [ "${i}" != "3" ]
        then
	    PASSWD=$(whiptail --title "get root permission" --passwordbox "input your root password by three chances" 10 60 3>&1 1>&2 2>&3)
        fi

        if [ ${i} = "3" ]; then
            whiptail --title "message" --msgbox "you have tried many times and do not get root permission, the script will exit!" 10 60
            exit 0
        fi
    
        sudo -k
        if sudo -lS &> /dev/null << EOF
${PASSWD}
EOF
        then
            i=10
        else
            if [ "${i}" != "2" ]
            then
                whiptail --title "get root permission" --msgbox "invalid password, please input corrent password!" 10 60 
            fi
        fi
    done
    
    echo ${PASSWD} | sudo ls > /dev/null 2>&1
    echo ""
    echo -e "\tyou have get root permission!"
    echo ""

fi








# 环境适配

type kill &> /dev/null && type pidof &> /dev/null && type whiptail &> /dev/null && type sudo &> /dev/null || (echo -e "\t环境适配错误！\n" && exit 1)
echo -e "\t环境适配成功！\n"






pcap_cap_time_s=10
pcap_filter_rule=""
pcap_save_dir="./output/pcap_files/capture.pcap"
log_save_dir="./output/log/demo.log"
arr_set_list=$(whiptail --title "select settings" --checklist \
	"                                      set arguments\n\n" 15 94 4 \
	"pcap_cap_time_s" ": set fetch time(s)(defult: 10)" OFF \
	"pcap_filter_rule" ": set filtering rules(defult: NULL)" OFF \
	"pcap_save_dir" ": set pcap_file path(defult: ./output/pcap_files/capture.pcap)" OFF \
	"log_save_dir" ": set log path(defult: ./output/log/demo.log)" OFF 3>&1 1>&2 2>&3)


if [[ $arr_set_list =~ "pcap_cap_time_s" ]]
then
	pcap_cap_time_s=$(whiptail --title "input box" --inputbox "please input the capture time(s)\n(e: 10, e: 0(all the time))" 10 60 10 3>&1 1>&2 2>&3)
fi


if [[ $arr_set_list =~ "pcap_filter_rule" ]]
then
	pcap_filter_rule=$(whiptail --title "input box" --inputbox "please input the filter rules\n\n(e: \n[dst port 80: 只接收 tcp/udp 的目的端口是 80 的数据包]\n[ehter dst 00:e0:09:c1:0e:82: 只接收以太网 mac 地址是 00:e0:09:c1:0e:82 的数据包]\n[not tcp: 只接收不使用 tcp 协议的数据包]\n[src host 192.168.1.177: 只接收源 ip 地址是 192.168.1.177 的数据包]\n)" 15 90 3>&1 1>&2 2>&3)
	# pcap_filter_rule=$(whiptail --title "checklist dialog" --radiolist \
	# pcap_fi"please select a filter rule" 15 60 4 \
	# pcap_fi"" "" OFF \
	# pcap_fi"" "" OFF \
	# pcap_fi"" "" OFF \
	# pcap_fi"" "" OFF 3>&1 1>&2 2>&3)
fi


if [[ $arr_set_list =~ "pcap_save_dir" ]]
then
	pcap_save_dir=$(whiptail --title "input box" --inputbox "please input the pcap_file path" 10 60 ./output/pcap_files/capture.pcap 3>&1 1>&2 2>&3)
fi


sudo touch $pcap_save_dir &> /dev/null
if [ ! -f "$pcap_save_dir" ]
then
	echo -e "\tcteate $pcap_save_dir failed!"
	exit 1
else
	echo -e "\tcteate $pcap_save_dir successfully!"
fi


if [[ $arr_set_list =~ "log_save_dir" ]]
then
	log_save_dir=$(whiptail --title "input box" --inputbox "input the path of log file(defult: ./output/log/demo.log)" 10 60 ./output/log/demo.log 3>&1 1>&2 2>&3)
fi


sudo touch $log_save_dir &> /dev/null
if [ ! -f "$log_save_dir" ]
then
	echo -e "\tcteate $log_save_dir failed!"
	exit 1
else
	echo -e "\tcteate $log_save_dir successfully!"
fi


echo -e "\033[33m\n\tpcap_cap_time_s(s): $pcap_cap_time_s\n\tpcap_filter_rule: $pcap_filter_rule\n\tpcap_save_dir: $pcap_save_dir\n\tlog_save_dir: $log_save_dir\033[0m"


sudo ./bin/capture_package "$pcap_cap_time_s" "$pcap_filter_rule" "$pcap_save_dir" &> $log_save_dir &


if [ $pcap_cap_time_s -eq 0 ]
then
	echo -e "\033[31m\n\tthe demo program is running in the background!\n\033[0m"
	whiptail --title "welcome" --msgbox "Press enter to terminate the process\n" 10 60
	kill -15 $(pidof "capture_package")
	echo -e "\033[31m\n\tsee $log_save_dir for log files!"
	echo -e "\tsee $pcap_save_dir for .pcap files!\n\033[47;30m"
	
	sleep 1
	tail_line=$(tail -n 1 $log_save_dir) # 输出捕获的数据包数量
	echo -e "$tail_line\033[0m\n"

	exit 0
fi







progress_bar_i=0
progress_bar_index_color=2 # 0(黑), 1(红), 2(绿), 3(黄), 4(蓝), 5(洋红), 6(青), 7(白)
progress_bar_color=$((30+progress_bar_index_color))
progress_bar_window_width=$(stty size|awk '{print $2}')
((progress_bar_window_width=progress_bar_window_width-13))
progress_bar_str_sharp=""
progress_bar_j=$(echo "scale=2; 100/${progress_bar_window_width}" | bc)
progress_bar_k=$(echo "scale=2; 100/${progress_bar_window_width}" | bc)
progress_bar_arr=("|" "/" "-" "\\")

echo -e "\033[36m\ntask progress: \033[0m" # 36 青色前景
while [ $progress_bar_i -le 100 ]
do
    progress_bar_index=$((progress_bar_i%4))

    if [ ${progress_bar_window_width} -le 100 ]
    then
        printf "\e[0;$progress_bar_color;1m[%-${progress_bar_window_width}s][%.2f%%] %c\r" "$progress_bar_str_sharp" "$progress_bar_i" "${progress_bar_arr[$progress_bar_index]}"

        if [ "$(echo "${progress_bar_i}>=${progress_bar_k}" | bc)" == "1" ]
        then
            progress_bar_str_sharp+='#'
            progress_bar_k=$(echo "scale=2; ${progress_bar_k}+${progress_bar_j}" | bc)
        fi

        if [ ${progress_bar_i} -eq 100 ]
        then
            printf "\e[0;$progress_bar_color;1m[%-${progress_bar_window_width}s][%.2f%%] %c\r" "$progress_bar_str_sharp" "$progress_bar_i" " "
            printf "\n"
        fi
    else
        if [ "$(echo "${progress_bar_i}>=${progress_bar_k}" | bc)" == "1" ]
        then
            while [ 1 ]
            do
                if [ "$(echo "${progress_bar_i}<=${progress_bar_k}" | bc)" == "1" ]
                then
                    break
                fi

                printf "\e[0;$progress_bar_color;1m[%-${progress_bar_window_width}s][%.2f%%] %c\r" "$progress_bar_str_sharp" "$progress_bar_i" "${progress_bar_arr[$progress_bar_index]}"

                progress_bar_str_sharp+='#'
                progress_bar_k=$(echo "scale=2; ${progress_bar_k}+${progress_bar_j}" | bc)
            done

            if [ ${progress_bar_i} -eq 100 ]
            then
                printf "\e[0;$progress_bar_color;1m[%-${progress_bar_window_width}s][%.2f%%] %c\r" "$progress_bar_str_sharp" "$progress_bar_i" " "
            fi
        fi
    fi
    progress_bar_i=$((progress_bar_i+1))

    sleep $(echo "scale=2; ${pcap_cap_time_s}/100" | bc)
done
echo -e "\033[0m"


echo -e "\033[31m\n\tsee $log_save_dir for log files!"
echo -e "\tsee $pcap_save_dir for .pcap files!\n\033[47;30m"

sleep 1 # 等待进程完全退出
tail_line=$(tail -n 1 $log_save_dir) # 输出捕获的数据包数量
echo -e "$tail_line\033[0m\n"


exit 0
