package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/lizongying/go-ip-utils/iputils"
)

func main() {
	ipv4F := flag.String("ipv4", "", "")
	flag.Parse()
	ipv4 := *ipv4F
	fmt.Printf("ipv4: %+v\n", ipv4)
	ips, _ := iputils.CidrToIps(ipv4)
	b, _ := json.Marshal(ips)
	fmt.Println(string(b))
}
