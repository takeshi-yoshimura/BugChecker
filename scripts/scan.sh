#!/bin/bash

if [ $# -ne 2 ]; then
  echo "specify (getentryexit subdir) (linux dir)"
  exit 1
fi
ID=`basename ${1}`
output=$(dirname $(dirname ${1}))/irqchecker/${ID}

mkdir -p ${output}
cd ${2}

clang=`which clang`
make CC=${clang} HOSTCC=${clang} mrproper allyesconfig prepare

/usr/bin/time -a -o ${output}/time.log cat ${1}/build_target.txt | \
  xargs scan-build -o ${output} -load-plugin bugchecker.so -enable-checker linux.irq \
  --use-analyzer=${clang} --use-cc=${clang} -analyze-headers -maxloop 10 \
  -disable-checker core -disable-checker unix -disable-checker deadcode -disable-checker security \
  make -i CC=${clang} HOSTCC=${clang} 2> ${output}/stderr > ${output}/stdout

mkdir -p /var/www/html/irq
mv ${output}/* /var/www/html/irq/

