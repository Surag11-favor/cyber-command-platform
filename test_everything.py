import subprocess
import time
import urllib.request
import json
import os

print("Starting Spring Boot App...")
app_proc = subprocess.Popen(["C:\\Program Files\\Java\\jdk-25\\bin\\java.exe", "-jar", "target/cyber-command-0.0.1-SNAPSHOT.jar"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(15)

print("Testing API...")
url = "http://localhost:8080/api/analysis/scan"
data = json.dumps({"content": "https://www.youtube.com/@theformivelyris"}).encode("utf-8")
headers = {"Content-Type": "application/json"}

req = urllib.request.Request(url, data=data, headers=headers, method="POST")

result = "FAILED"
try:
    with urllib.request.urlopen(req, timeout=10) as response:
        result = response.read().decode("utf-8")
        print("Success!")
except Exception as e:
    result = f"Error: {e}"
    print(result)

with open("final_result_yt.txt", "w") as f:
    f.write(result)

print("Cleaning up...")
app_proc.terminate()
