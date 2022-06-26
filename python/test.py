import subprocess

def run_scripts(s):
    e = {"TEST":"1"}
    r = subprocess.run(s, stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL, env=e)
    ret = r.stdout.decode("utf-8").strip()
    print(ret)
    print(e)

s = "export TEST=2; echo OK"
run_scripts(s)
