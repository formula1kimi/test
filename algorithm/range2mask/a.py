#!/bin/python3

"""
将数值的范围比较，使用mask来完成
一个mask匹配规则为一个数和一个mask的组合，实际上代表一个匹配成功的空间。
比如：0b0100/0b1100表示0b0100~0b0111都匹配此规则，因为他们和0b1100与运算后都等于0x0100。
算法的实质就是将n1到n2区间用多个上面的规则进行覆盖，一个数只要被其中一个规则匹配上，就说明在这个区间内。
Mask尾部的0越多，则能覆盖的范围越大。为了减少rule的数量，必须尽量使用大的Mask。
所有可以作为mask开始的数，必须是尾部有0的。我们就是在这个区间中找到这些数来划分区间。
这个算法从n1开始，不断的寻找合适rule来覆盖这个区间，直到刚刚好把n2覆盖进去。
"""

import argparse
from typing import List

def zero_trail_num(n):
    for zn in range(1, 32):
        mask = ((1 << zn) - 1)
        mask_n = n & mask
        if mask_n == 0:
            continue
        else:
            return zn-1


def range2match(n1, n2):
    rules = []
    n = n1
    while n <= n2:
        # 当前数值在二进制上，末尾有几个0
        zn = zero_trail_num(n)
        while zn >= 0:
            if zn == 0:
                # 如果一个0都没有，无法用更多的mask来匹配，只能用全1.
                # 这个数只能用这个rule来匹配。
                r = (n, 0xFFFFFFFF)
                rules.append(r)
                # 从下一个数继续开始
                n = n + 1
                break
            else:
                # 查看用n和n的末尾0个数组成的mask的规则，可以覆盖到最大的数是多少：nx
                nx = n | ((1 << zn) - 1) 
                if nx <= n2:
                    # nx没有超过n2的大小，我们添加这个规则。
                    r = (n, (0xffffffff>>zn)<<zn)
                    rules.append(r)
                    # 从下一个数继续开始。nx + 1 实际上一定是比当前的n多了1个0. 是一个更大的范围。
                    # 问题挑战：前面计算出来的rules，是否可以合并成一个大的rule?
                    n = nx + 1
                    break
                else:
                    # 说明当前的zn作为mask的范围太大，超过n2。只能尝试减小zn，找到最合适的zn。
                    zn = zn - 1
    return rules

def test_match(rules, n):
    for r in rules:
        if (n & r[1]) == r[0]:
            return True
    return False
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("start", type=int)
    parser.add_argument("end", type=int)
    args = parser.parse_args()
    rules = range2match(args.start, args.end)
    for r in rules:
        print(f"rule: 0x{r[0]:08x}/0x{r[1]:08x}")
    
    tmax = 0xFFFF
    for i in range(0, tmax):
        b1 = test_match(rules, i)
        b2 = (args.start <= i <= args.end)
        if b1 != b2:
            print(f"Test failed for number: {i}, match return {b1}")
            break

if __name__ == '__main__':
    main()


