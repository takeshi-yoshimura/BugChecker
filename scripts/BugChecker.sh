#!/bin/sh

if [ $# -ne 2 ]; then
    echo "usage: ${0} (linux dir path) (output dir path)"
    exit 1
fi

if [ "${1}" = "${2}" ]; then
	echo "output dir must be different from ${1}"
	exit 1
fi

if [ ! -d "${1}" ]; then
	echo "linux dir is not found"
	exit 1
fi

if [ ! -d "linux_patch" ]; then
	echo "linux_patch directory is not found"
	echo "this script must be executed by like ./script/instrumet.sh"
	exit 1
fi

if [ ! -d "scripts" ]; then
	echo "scripts directory is not found"
	echo "this script must be executed by like ./script/instrument.sh"
	exit 1
fi

curr=`pwd`
workDir=${2}

reBuild="y"
if [ -d "${workDir}" ]; then
	echo "${workDir} exists."
	while true; do
		echo "do you want to re-instrument? [y or n]"
		read reBuild
		case ${reBuild} in
			y)
				echo "re-instrument code"
				break
				;;
			n)
				echo "skip instrumentation. re-use the past instrumentation."
				break
				;;
		esac
	done

	if [ "${reBuild}" = "n" ]; then
		if [ ! -d "${workDir}/stat" ]; then
			echo "${workDir}/stat is not found. re-instrument"
			reBuild="y"
		elif [ ! -d "${workDir}/models" ]; then
			echo "${workDir}/models is not found. re-instrument"
			reBuild="y"
		fi
	fi

	sleep 1s
	if [ "${reBuild}" = "y" ]; then
		while true; do
			echo "are you OK if ${workDir} is removed? [y or n]"
			read removeIsOK
			case ${removeIsOK} in
				y)
					rm -rf ${workDir}
					echo "${workDir} is removed"
					break
					;;
				n)
					echo "OK. exit this script"
					exit 1
					break
					;;
			esac
		done
	fi
fi


if [ "${reBuild}" = "y" ]; then
	echo "copy the original linux directory from ${1} to ${workDir}."
	cp -r ${1} ${workDir}
	echo "copy the models of drivers with which codes are instrumented" 
	cp -r models ${workDir}

	echo "apply some patches in order to build linux by clang"
	cd ${workDir}
	ver=`git describe master | cut -d - -f1`
	git checkout master
	patch -p 1 < ${curr}/linux_patch/${ver}

	echo "start getting the entry and exit points of device drivers"
	sleep 5s
	make mrproper allyesconfig
	${curr}/scripts/scan-build2 -enable-checker linux.GetEntryExit \
		make CC=/usr/local/bin/clang HOSTCC=/usr/local/bin/clang -i drivers/ -j 8
	echo "finish getting the entry and exit points of  device drivers"
	sleep 5s

	echo "gather .entry files and generate stats"
	mkdir -p stat
	find . -name "*.entry" -exec cat {} \; > stat/entry.txt
	python ${curr}/scripts/traverse.py < stat/entry.txt > stat/traverse.txt
    sed -i -e '/WARNING/d' stat/traverse.txt

	grep "free_irq" stat/traverse.txt | \
		grep -v "request_threaded_irq" | grep -v "request_any_context_irq" | \
		grep -v "devm_request_threaded_irq" | \
		cut -d "	" -f1 | sort | uniq -c | sed -e 's/^\s\+//g' | grep "struct" | \
		sed -e 's/struct //g' | LANG=en_EN sort -n -r > stat/free_irq.txt
	cut -d " " -f2 stat/free_irq.txt > stat/free_irq_functions.txt

	grep -e "request_threaded_irq" -e "request_any_context_irq" \
		-e "devm_request_threaded_irq" stat/traverse.txt | \
		cut -d "	" -f1 | sort | uniq -c | sed -e 's/^\s\+//g' | grep "struct" | \
		sed -e 's/struct //g' | LANG=en_EN sort -n -r > stat/request_irq.txt
	cut -d " " -f2 stat/request_irq.txt > stat/request_irq_functions.txt

	echo "generate instrumented .c files"
	python ${curr}/scripts/instrument.py < stat/traverse.txt

	echo "finish instrumentation"
	cd ${curr}
fi

echo "start analyzing device drivers"
sleep 5s

cd ${workDir}
mkdir -p stat/scan-build/
make mrproper allyesconfig
cat stat/build_target.txt | xargs ${curr}/scripts/scan-build2 -o stat/scan-build -enable-checker linux.IRQChecker -enable-checker unix.Malloc \
	make CC=/usr/local/bin/clang HOSTCC=/usr/local/bin/clang -i -j 8

