// Small Go discovery fixture. Build with -trimpath -ldflags="-s -w".
package main

var fixtureHeader = "EAOS_GO_STATIC_HEADER"

//go:noinline
func fixtureAlpha(value int) string {
    if value > 5 { return "EAOS_GO_PACKED_ALPHA" }
    return "EAOS_GO_PACKED_BETA"
}

//go:noinline
func fixtureStrings(value int) {
    println("EAOS_GO_SHARED_PHRASE")
    println("EAOS_GO_SHARED_PHRASE with a longer tail")
    println("EAOS_GO_ZERO\x00END")
    println("EAOS_GO_世界")
    println(fixtureHeader)
    println(fixtureAlpha(value))
}

func main() { fixtureStrings(7) }
