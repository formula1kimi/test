package main
import "fmt"

func t1() {
    var a [8]int = [8]int{1,2,3,4,5,6,7,8}
    var s []int = a[3:4]
    fmt.Printf("a = %v\n", a)
    fmt.Printf("s = %v\n", s)
    t("Hello", 1,2,3,4,5,6)
}

func t(x string, nums ...int) {
    fmt.Print(x)
    for n := range nums {
        fmt.Print(n)
    }
    fmt.Println()
}

type A struct {
    Name string
}

func (a *A) PrintName() {
    fmt.Println(*a)
}

type B struct {
    A
}

func (b *B) PrintName() {
    fmt.Print("in B: ")
    b.A.PrintName()
}

func main1() {
    a := A{Name:"aaaaaa"}
    b := B{A:A{Name:"bbbbbb"}}
    b.A.Name="xxxx"
    b.Name="yyy"
    a.PrintName()
    b.PrintName()
}

type Integer int

func (i Integer) Add(x int) Integer {
    return Integer(int(i) + x)
}

type Float float64

func (f Float) Add(x int) Integer {
    return Integer(int(f) + x)
}

func (f Float) AddFloat(x float64) Float {
    return Float(float64(f) + float64(x))
}


type IInteger interface {
    Add(x int) Integer
}

type IFloat interface {
    Add(x int) Integer
    AddFloat(x float64) Float
}


func main2() {
    var f Float = 2.4
    var iff IFloat = f
    var ii IInteger = iff
    x := ii.Add(100)
    fmt.Println(x)

    iff,ok := ii.(IFloat)
    if ok {
        m := iff.AddFloat(100)
        fmt.Println(m)
    }
}

func main() {
    ch := make(chan int, 1)
    for {
        select {
            case ch <- 0:
            case ch <- 1:
        }
        i := <-ch
        fmt.Println("Value received:", i)
    }
}

