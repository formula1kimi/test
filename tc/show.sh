 #!/bin/bash
 
for id in $(cat ids.txt); do echo "----$id----"; ~/opt/ppio/pairat/ssh.sh -p 58779 -l root $id 'curl -Ss https://pi-miner.oss-cn-beijing.aliyuncs.com/net-config/tc-show.sh | bash | head -n 10 | grep htb -A2' ; done
