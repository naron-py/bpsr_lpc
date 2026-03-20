import subprocess

with open("out.log", "w", encoding="utf-8") as f:
    subprocess.run(["python", "dbg.py"], stdout=f, stderr=subprocess.STDOUT)
