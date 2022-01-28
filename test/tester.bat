@echo off
REM
REM test harness for scanner.py
REM
echo
echo  basic test harness for 
echo
echo  vtpy and validators are required from pypi  
echo
echo   usage:
echo   scanner.py --help <subcommand> [files ...]
echo
echo  I seem to have found a bug in argparse 
echo     that one one occasion prints usage twice
pause
echo cleanup old files "*.scan*
pause
del /p *.scan*
echo calling scanner init
pause
scanner.py init
dir *.scanr*
more .scanrc
pause
echo calling scanner scan test2.txt
scanner.py scan test2.txt
dir *.scanr*
more .scanrc
pause
echo calling scanner scan test2.txt (with bad command)
scanner.py sacn test1.txt test2.txt
dir *.scanr*
more .scanrc
pause
echo calling scanner with file not found 
scanner.py scan mixeddata test1.txt test2.txt
dir *.scanr*
more .scanrc
pause



