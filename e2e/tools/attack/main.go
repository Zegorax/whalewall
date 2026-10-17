// Command attack contains the hostile client behaviors the end-to-end
// scenarios run inside containers: raw packets with a forged source
// address and floods of DNS queries and connections.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: attack spoof|flood|hold ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "spoof":
		spoof(os.Args[2:])
	case "flood":
		flood(os.Args[2:])
	case "hold":
		hold(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// spoof sends one UDP packet with a forged source address using a raw
// socket, which containers have with the default capabilities.
func spoof(args []string) {
	fs := flag.NewFlagSet("spoof", flag.ExitOnError)
	src := fs.String("src", "", "forged source address")
	dst := fs.String("dst", "", "destination address")
	port := fs.Int("port", 9999, "destination port")
	msg := fs.String("msg", "spoofed", "payload")
	_ = fs.Parse(args)

	s4 := net.ParseIP(*src).To4()
	d4 := net.ParseIP(*dst).To4()
	if s4 == nil || d4 == nil {
		fmt.Fprintln(os.Stderr, "need IPv4 addresses")
		os.Exit(2)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Println("raw socket not allowed:", err)
		os.Exit(1)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		fmt.Println("IP_HDRINCL:", err)
		_ = syscall.Close(fd)
		os.Exit(1)
	}

	payload := []byte(*msg)
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], uint16(*port))
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	ip[8] = 64
	ip[9] = syscall.IPPROTO_UDP
	copy(ip[12:], s4)
	copy(ip[16:], d4)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))

	var to syscall.SockaddrInet4
	copy(to.Addr[:], d4)
	err = syscall.Sendto(fd, append(ip, udp...), 0, &to)
	_ = syscall.Close(fd)
	if err != nil {
		fmt.Println("sendto:", err)
		os.Exit(1)
	}
	fmt.Println("sent")
}

// flood sends UDP DNS queries as fast as it can from many goroutines and
// opens idle TCP connections, then prints how many answers it got.
func flood(args []string) {
	fs := flag.NewFlagSet("flood", flag.ExitOnError)
	server := fs.String("server", "", "DNS server host:port")
	name := fs.String("name", "a.corp.test.", "name to query")
	n := fs.Int("n", 2000, "number of UDP queries")
	workers := fs.Int("workers", 50, "concurrent senders")
	conns := fs.Int("tcp", 0, "idle TCP connections to open")
	_ = fs.Parse(args)

	start := time.Now()
	var answered, refused, lost atomic.Int64
	var wg sync.WaitGroup
	work := make(chan struct{}, *n)
	for range *n {
		work <- struct{}{}
	}
	close(work)
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dns.Client{Net: "udp", Timeout: 700 * time.Millisecond}
			for range work {
				m := new(dns.Msg)
				m.SetQuestion(*name, dns.TypeA)
				resp, _, err := c.Exchange(m, *server)
				switch {
				case err != nil:
					lost.Add(1)
				case resp.Rcode == dns.RcodeSuccess:
					answered.Add(1)
				default:
					refused.Add(1)
				}
			}
		}()
	}
	var open []net.Conn
	for range *conns {
		c, err := net.DialTimeout("tcp", *server, time.Second)
		if err == nil {
			open = append(open, c)
		}
	}
	wg.Wait()
	seconds := int(time.Since(start).Seconds()) + 1
	// how many of the idle connections are still open?
	alive := 0
	for _, c := range open {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); isTimeout(err) {
			alive++
		}
	}
	fmt.Printf("answered=%d refused=%d lost=%d tcp_opened=%d tcp_alive=%d seconds=%d\n", answered.Load(), refused.Load(), lost.Load(), len(open), alive, seconds)
}

// hold opens TCP connections and keeps them idle for a while.
func hold(args []string) {
	fs := flag.NewFlagSet("hold", flag.ExitOnError)
	server := fs.String("server", "", "host:port")
	n := fs.Int("n", 100, "connections")
	d := fs.Duration("for", 5*time.Second, "how long to hold them")
	_ = fs.Parse(args)

	var open []net.Conn
	for range *n {
		c, err := net.DialTimeout("tcp", *server, time.Second)
		if err == nil {
			open = append(open, c)
		}
	}
	time.Sleep(*d)
	alive := 0
	for _, c := range open {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); isTimeout(err) {
			alive++
		}
	}
	fmt.Printf("opened=%d alive=%d\n", len(open), alive)
}
