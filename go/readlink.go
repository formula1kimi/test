package main
import "os"
import "path/filepath"
import "fmt"

func main() {
    lpath := os.Args[1]
    entries, err := os.ReadDir(lpath)
    if err != nil {
        fmt.Printf("error: %s\n", err)
        return
    }
    for _, e := range entries {
        epath := lpath + "/" + e.Name()
        rpath, err := filepath.EvalSymlinks(epath)
        if err != nil {
            fmt.Printf("%s -> error: %s\n", epath, err)
        } else {
            fmt.Printf("%s -> %s\n", epath, rpath)
        }
    }
}
