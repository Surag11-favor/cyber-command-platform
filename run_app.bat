@echo off
set "JAVA_HOME=C:\Program Files\Java\jdk-25"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "MYSQL_URL=jdbc:mysql://localhost:3306/frauddb?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
set "MYSQLUSER=root"
set "MYSQLPASSWORD="
set "PORT=8080"
"%JAVA_HOME%\bin\java.exe" -Dspring.profiles.active=dev -jar target/fraud-intel-0.0.1-SNAPSHOT.jar
