package main

import (
	"ipid/test"
)

func main() {
	test.Main("../../targets/tcp/80/2025-04-20_19-05-04/targets.csv")
	//if len(os.Args) != 2 {
	//	fmt.Println("Error: Mode not specified")
	//	return
	//}
	//mode := os.Args[1]
	//switch mode {
	//case "b2b":
	//	b2b.Main()
	//case "seq":
	//	seq.Main()
	//default:
	//	fmt.Println("Unknown mode:", mode)
	//}
}
