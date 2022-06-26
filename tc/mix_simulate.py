#!/bin/python3
from prettytable import PrettyTable

# Bandwidth generator to generate the bandwidth pattern
class BaseBandwidthGenerator:
    def __init__(self):
        pass

    def generate(self, n: int):
        return 0

# Always generate same bandwidth
class FixedBandWidth(BaseBandwidthGenerator):
    def __init__(self, base=0):
        self.base = base

    def generate(self, n: int) -> float:
        return self.base

# Gradually up & down 
class GradUpDown(BaseBandwidthGenerator):
    UP=1
    DOWN = 0
    def __init__(self, low=0, high=100, step=1):
        self.direct = self.UP
        self.low = low
        self.high = high
        self.step = step
        self.cur = low

    def generate(self, n: int) -> float:
        if self.direct == self.UP:
            self.cur += self.step
            if self.cur > self.high:
                self.cur = self.high
                self.direct = self.DOWN
        else:
            self.cur -= self.step
            if self.cur < self.low:
                self.cur = self.low
                self.direct = self.UP
        return self.cur

class Task:
    def __init__(self, prio = 0, ceil: float = 0, cr: float = 1, bw_gen:BaseBandwidthGenerator = None):
        self.bw: float = 0
        self.prio: int = prio
        self.ceil = ceil
        self.ceilR = cr 
        self.bw_gen = bw_gen

    def next_bw(self, n: int):
        if self.bw_gen:
            self.bw = self.bw_gen.generate(n)
        if self.bw > self.ceil:
            self.bw = self.ceil

class BaseController:
    def __init__(self):
        self.max_ceil = 0
        self.est_ceil = 0
        self.est_ceil_history = []
    
    def control(self, a: Task, b: Task):
        raise Exception("not impl")

class Controller2(BaseController):
    def __init__(self):
        super(Controller2, self).__init__()

    def control(self, a: Task, b: Task):
        a.ceil = max(a.bw * a.ceilR, 10)
        b_ceil = b.bw * b.ceilR
        self.est_ceil = min(a.ceil + b_ceil, 100)
        if self.max_ceil < self.est_ceil:
            self.max_ceil = self.est_ceil
        b.ceil = max(self.max_ceil - a.ceil, 10)

class Controller3(BaseController):
    def __init__(self):
        super(Controller3, self).__init__()

    def control(self, a: Task, b: Task):
        a_ceil = max(a.bw * a.ceilR, 10)
        b_ceil = max(b.bw * b.ceilR, 10)
        if a_ceil + b_ceil < 100:
            a.ceil = a_ceil
            b.ceil = b_ceil
        elif a.prio:
            a.ceil = min(100, a_ceil)
            b.ceil = max(100-a.ceil, 10)
        else:
            r = max(100-a.bw-b.bw, 0)
            a.ceil = a.bw + r/2
            b.ceil = b.bw + r/2
        # max_ceil, est_ceil is not useful.
        self.est_ceil = min(a.ceil + b.ceil, 100)
        if self.max_ceil < self.est_ceil:
            self.max_ceil = self.est_ceil


def main():
    a = Task(prio=1, ceil = 50, cr=1.5, bw_gen=GradUpDown(0, 80, 10))
    #a = Task(prio=1, ceil = 50, cr=1.2, bw_gen=FixedBandWidth(30))
    b = Task(prio=0, ceil = 50, cr=1.5, bw_gen=FixedBandWidth(40))
    c = Controller3()

    pt = PrettyTable()
    pt.field_names = ['i', 'a.bw', 'a.ceil', 'b.bw', "b.ceil", "est_ceil", "max_ceil", "total_bw"]
    pt.align = 'l'
    pt.float_format="0.1"
 
    for i in range(0, 30):
        # import pdb; pdb.set_trace()
        a.next_bw(i)
        b.next_bw(i)
        c.control(a, b)
        row = [i, a.bw, a.ceil, b.bw, b.ceil, c.est_ceil, c.max_ceil, a.bw + b.bw]
        pt.add_row(row)
    print(pt)


if __name__ == "__main__":
    main()