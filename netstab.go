package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func ping(addr string, count int) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer conn.Close()

	for i := 0; i < count; i++ {
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  i,
				Data: []byte("HELLO-PING"),
			},
		}

		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			fmt.Printf("Error marshaling message: %v\n", err)
			continue
		}

		start := time.Now()
		_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: net.ParseIP(addr)})
		if err != nil {
			fmt.Printf("Ping %d: Failed to send packet\n", i+1)
			continue
		}

		reply := make([]byte, 1500)
		err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			fmt.Printf("Error setting deadline: %v\n", err)
			continue
		}

		_, _, err = conn.ReadFrom(reply)
		if err != nil {
			fmt.Printf("Ping %d: Request timed out\n", i+1)
			continue
		}

		duration := time.Since(start)
		fmt.Printf("Ping %d: Response time = %.2f ms\n", i+1, float64(duration.Milliseconds()))
		time.Sleep(time.Second)
	}
}

func checkNAT() {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Printf("Error checking NAT: %v\n", err)
		return
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Printf("Local IP: %v\n", localAddr.IP)

	// Basic NAT check
	if localAddr.IP.IsPrivate() {
		fmt.Println("NAT Type: Private NAT")
	} else {
		fmt.Println("NAT Type: Full Cone")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./netstab <hostname>")
		os.Exit(1)
	}

	host := os.Args[1]
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		fmt.Printf("Could not resolve %s: %v\n", host, err)
		os.Exit(1)
	}

	fmt.Printf("Testing network stability to %s (%s)\n", host, ip.String())
	checkNAT()
	ping(ip.String(), 5)
}
