package main
import "math"
import "fmt"
import "flag"

func work(id int) {
    var i float64 = 0
    fmt.Printf("Start work %d\n", id)
    for {
        math.Log2(i)
        i = i + 1
        if i > 10000000.0 {
            i = 0
        }
    }
}

func main() {
    c := flag.Int("c", 1, "goroutine count")
    flag.Parse()
    p := make(chan int)
    for i := 0; i < *c; i++ {
        go work(i)
    }
    for i := 0; i < *c; i++ {
        <-p
    }
    fmt.Println("Exited")

}
