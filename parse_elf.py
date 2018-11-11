#!/usr/bin/python
# By Qiuyu Xiao <qiuyu.xiao.qyx@gmail.com>, 2018

import re
import sys
import subprocess

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Please specify executable file path."

    proc = subprocess.Popen(['file', sys.argv[1]], stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    # Make sure the file type is x86-64 ELF
    m = re.match('.*ELF 64-bit LSB executable, x86-64.*', stdout)
    if not m:
        print "Not an x86-64 ELF executable file."

    proc = subprocess.Popen(['objdump', '-d', '--insn-width=16', \
                            sys.argv[1]], stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    # Match the ascii representation of the x86-64 instruction
    regex = re.compile(' *[0-9a-f]+:\\t(([0-9a-f]{2} )+) *\\t.*')

    for line in stdout.split('\n'):
        m = regex.match(line)
        if m:
            print m.group(1).replace(' ', '')
