#!/bin/bash

if [ $# -lt 2 ]; then
  Help="`clang -cc1 -analyzer-checker-help`"
  echo -e "usage: ${0} {checker-name} {test.c}\n\nclang help:\n${Help}" | less
  exit 1
fi
checker_name=${1}
options=(`clang -### -c ${2} 2>&1 | sed -e 's/\s\+/\n/g'`)
inludes=()
i=0
while [ $i -lt ${#options[*]} ]; do
  if [ "`echo ${options[$i]} | grep -c isystem`" == "1" ]; then
    includes+=(`echo ${options[$i]} | sed -e 's/"//g'`)
    i=`expr $i + 1`
    includes+=(`echo ${options[$i]} | sed -e 's/"//g'`)
  fi
  i=`expr $i + 1`
done

clang -cc1 ${includes[@]} -load bugchecker.so -analyze -analyzer-checker=${1} ${2}

