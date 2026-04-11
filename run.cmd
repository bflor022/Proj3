@echo off
echo Starting Server...
start cmd /k python server.py

echo Delay to give the server a chance to start
timeout /t 2 >nul

echo Starting Client...
start cmd /k python client.py
