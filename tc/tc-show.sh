#!/bin/bash
burst=$((128 * 1024 * 1024))
devs=$(ip --br a | grep wan | awk '{print $1}' | awk -F@ '{print $2}' | awk -F. '{print $1}' | sort -u)
echo "devices = $devs"
if [ -z "$devs" ]; then
    echo "no dev selected"
    exit 1
fi

data="
01729eb0d1f97c64480414d4d2d26d8b		5
0979044eb8554560ae18e36d7363eea9		5.31
1d64540aa182b94bbb314d52e5303cf3		4.06
384370ae34be75b11a659a748ca08c40		4.53
5cb014926d3273127aaf76528fd8707f		4.53
75bbaa667c336c5c4125b2e2ec068192		5.31
85621bc5445a6984682fbe4c92c53e21		4.98
afb54f13303a39872eac1480cbed0217		4.98
0ae0e9ccaac9803bcae16cd125d1150b		0.98
63293e851eb43a1a983cda2ccadadc4f		2.93
9e2e19f782981052bc6ff6152e6a4e35		0.98
a3c7e3f1a35183ce0d3d94f9ebea5b79		2.93
b116e804404d2cdda4054e2e72d72820		0.98
b25da0eaaf498bb4d771a14800f895fe		2.93
cbb297a667ac2317e3827c1292589412		0.98
d4dc165e69bac550c5b071c05625be9d		0.98
f0a6af98ff822af8c40c6c9f0813ff5b		1.56
f7182efab3faebd2432d822ff083eab5		0.98
200a50bd4ec6cd9203d7d9c57f0d4209		5
61f3e6f4a85e75ef0fe56dfa7a7b9a1a		5
8c0018cb417ebf83ce653e222b74c97b		5
b836f19327a2847d534f3cade5450ba1		5
d2178ab571cc7a420e7a22dc1acafc43		5
"

id=$(cat /etc/machine-id)
echo $id
rate=$(echo "$data" | grep $id | awk '{print $2}')
if [ -z "$rate" ]; then
    echo "id not found"
    exit 1
fi

rate=$(echo "$rate * 1000" | bc)
rate="${rate%.*}"
echo "rate = $rate"

for dev in $devs; do
    echo "tc stat of dev $dev:"
    tc -s class show dev $dev
done


