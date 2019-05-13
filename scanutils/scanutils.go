package scanutils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

type PortRange struct {
	Start int
	End   int
}

type host struct {
	IPv4       string
	Hostname   string
	PrettyName string
	OpenPorts  []int
	mutex      sync.Mutex
	lock       *semaphore.Weighted
}

type CIDR struct {
	Hosts []*host
}

// Helper function to validate IPv4
func ValidIPv4(host string) bool {
	parts := strings.Split(host, ".")

	if len(parts) < 4 {
		return false
	}

	for _, x := range parts {
		if i, err := strconv.Atoi(x); err == nil {
			if i < 0 || i > 255 {
				return false
			}
		} else {
			return false
		}

	}
	return true
}

// Validates that a new host can be created based on hostName
func NewHost(hostName string) (*host, error) {
	mtx := sync.Mutex{}
	if ValidIPv4(hostName) {
		return &host{
			IPv4:       hostName,
			PrettyName: hostName,
			mutex:      mtx,
			lock:       semaphore.NewWeighted(100), // yeah i hardcoded don't @me
		}, nil
	} else {
		// Try and lookup the hostname
		ips, err := net.LookupIP(hostName)
		if err != nil {
			return nil, err
		}
		hostStr := fmt.Sprintf("%s (%s)", ips[0].String(), hostName)
		return &host{
			IPv4:       ips[0].String(),
			Hostname:   hostName,
			PrettyName: hostStr,
			mutex:      mtx,
			lock:       semaphore.NewWeighted(100),
		}, nil
	}
}

func NewCIDR(cidrStr string) (*CIDR, error) {
	ip, ipnet, err := net.ParseCIDR(cidrStr)
	var hosts []*host
	// Maybe single IP given?
	if err != nil {
		hostInst, err := NewHost(cidrStr)
		// Failed to parse the single ip. Fail out.
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, hostInst)
	} else {
		var ips []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
		// remove network address and broadcast address
		for i := 1; i < len(ips)-1; i++ {
			hostInst, err := NewHost(ips[i])
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, hostInst)
		}
	}
	return &CIDR{
		Hosts: hosts,
	}, nil
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Scan a single port!
func (server *host) ScanPort(port int, timeout time.Duration) {
	target := fmt.Sprintf("%s:%d", server.IPv4, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if conn != nil {
		conn.Close()
	}

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") || strings.Contains(err.Error(), "termorarily unavailable") {
			time.Sleep(timeout)
			server.ScanPort(port, timeout)
		}
		return
	}
	server.mutex.Lock()
	server.OpenPorts = append(server.OpenPorts, port)
	server.mutex.Unlock()
}

// Scan a sequential range of ports
func (server *host) ScanPortRange(pr PortRange, timeout time.Duration) {
	wg := sync.WaitGroup{}

	for port := pr.Start; port <= pr.End; port++ {
		server.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer server.lock.Release(1)
			defer wg.Done()
			server.ScanPort(port, timeout)
		}(port)
	}
	wg.Wait()
}

// Scan a smattering of ports based on the slice.
func (server *host) ScanPortRanges(portList []PortRange, waitTime time.Duration) {
	// maybe start threading scan here
	// lim := Ulimit() / 2

	for i := 0; i < len(portList); i++ {
		server.ScanPortRange(portList[i], waitTime)
	}
}

func (cidrRange *CIDR) ScanHosts(portList []PortRange, waitTime time.Duration) {
	wg := sync.WaitGroup{}
	for i := 0; i < len(cidrRange.Hosts); i++ {
		server := cidrRange.Hosts[i]
		wg.Add(1)
		go func(server *host, portList []PortRange, waitTime time.Duration) {
			defer wg.Done()
			server.ScanPortRanges(portList, waitTime)
		}(server, portList, waitTime)
	}
	wg.Wait()
}

func (server *host) PrintOpenPorts() {
	if len(server.OpenPorts) == 0 {
		return
	}
	fmt.Printf("Scan results for %s:\n", server.PrettyName)
	totalWhiteSpace := 6
	for i := 0; i < len(server.OpenPorts); i++ {
		fmt.Printf("\t%d%sopen\n", server.OpenPorts[i], strings.Repeat(" ", totalWhiteSpace-len(strconv.Itoa(server.OpenPorts[i]))))
	}
	fmt.Println()
}

func (server *host) GreppableString() string {
	if len(server.OpenPorts) == 0 {
		return ""
	}
	totalWhiteSpace := 45 // arbitrary amt
	padding := totalWhiteSpace - len(server.PrettyName)
	if padding < 1 {
		padding = 1
	}
	portString := "("
	for i := 0; i < len(server.OpenPorts); i++ {
		addStr := fmt.Sprintf("%d/open", server.OpenPorts[i])
		if i != (len(server.OpenPorts) - 1) {
			addStr += ", "
		}
		portString += addStr
	}
	portString += ")"
	line := fmt.Sprintf("%s%s%s", server.PrettyName, strings.Repeat(" ", padding), portString)
	return line
}

func (cidrRange *CIDR) PrintOpenPorts() {
	for i := 0; i < len(cidrRange.Hosts); i++ {
		cidrRange.Hosts[i].PrintOpenPorts()
	}
}

// Bad ulimit funciton which was supposed to bound semaphores (surprise; it didn't.)
// func Ulimit() int64 {
// 	out, err := exec.Command("ulimit", "-n").Output()
// 	if err != nil {
// 		if strings.Contains(err.Error(), "too many open files") || strings.Contains(err.Error(), "temporarily unavailable") {
// 			time.Sleep(500 * time.Millisecond)
// 			return Ulimit()
// 		}
// 		fmt.Printf("Error fetching Ulimit: %s\n", err.Error())
// 		return -1
// 	}

// 	s := strings.TrimSpace(string(out))

// 	i, err := strconv.ParseInt(s, 10, 64)
// 	if err != nil {
// 		panic(err)
// 	}

// 	return i
// }
