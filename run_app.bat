@echo off
set "JAVA_HOME=C:\Program Files\Java\jdk-25"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "PORT=8080"
"%JAVA_HOME%\bin\java.exe" -Dspring.profiles.active=dev -jar target/cyber-command-0.0.1-SNAPSHOT.jar

