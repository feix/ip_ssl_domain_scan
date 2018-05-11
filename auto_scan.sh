#!/bin/bash


exit_msg() {
    echo $@ &>2
    exit 1
}

routes=chnroutes.txt
wget -q http://f.ip.cn/rt/${routes} -O ${routes} || exit_msg "download $routes failed"
python3 scan.py $target `grep -Ev '^#' $routes`
