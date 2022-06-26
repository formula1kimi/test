package main
//import "time"
import "fmt"
import "flag"

const N = 1
type Data struct {
    data [1024*1024*N]byte;
}

func main() {
    c := flag.Int("c", 100000, "memory allocate count")
    flag.Parse()
    bb := []*Data{}
    for i := 0; i < *c; i++ {
        fmt.Printf("%d: %dMB\n", i, N*(i+1))
        d := Data{}
        bb = append(bb, &d)
        //time.Sleep(time.Second)
    }
    fmt.Println("Press enter to exit...")
    fmt.Scanln()
    fmt.Println("Exited")
}
