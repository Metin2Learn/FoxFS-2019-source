@echo off
set PATH=tools\Python27;tools;%PATH%
if %1!==! goto build_with_param
set arg1=%1
"archiver" make_xml/%1_create.xml
"archiver" xml/%1_create.xml
echo "Done"
goto end
:build_with_param
set /p id="Enter File to make: " %=%
"archiver" make_xml/%id%_create.xml
"archiver" xml/%id%_create.xml > output.txt
echo "Done"
pause
:end
echo "Finished Execution"