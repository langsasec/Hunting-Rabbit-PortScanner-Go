package main

import (
    "flag"
    "fmt"
    "net"
    "strconv"
    "strings"
    "sync"
    "time"
)

func checkHostAlive(host string, port int, timeout time.Duration) bool {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
    if err == nil {
        defer conn.Close()
        return true
    }
    return false
}

func scanPort(host string, port int, timeout time.Duration, results chan int, wg *sync.WaitGroup) {
    defer wg.Done()
    if checkHostAlive(host, port, timeout) {
        results <- port
    }
}

func scanHost(host string, ports []int, timeout time.Duration, verbose bool) []int {
    openPorts := []int{}
    wg := sync.WaitGroup{}
    results := make(chan int)
    for _, port := range ports {
        wg.Add(1)
        go scanPort(host, port, timeout, results, &wg)
    }
    go func() {
        wg.Wait()
        close(results)
    }()
    for port := range results {
        openPorts = append(openPorts, port)
    }
    if verbose {
        if len(openPorts) > 0 {
            fmt.Printf("%s is alive\n", host)
            fmt.Printf("%s has open ports: %v\n", host, openPorts)
        } else {
            fmt.Printf("%s is not alive\n", host)
        }
    }
    return openPorts
}

func parsePorts(portRange string) []int {
    ports := []int{}
    if portRange == "" {
        ports = []int{21,22,23,25,53,80,81,88,89,110,113,119,123,135,139,143,161,179,199,389,427,443,445,465,513,514,
            515,543,544,548,554,587,631,646,873,902,990,993,995,1080,1433,1521,1701,1720,1723,1755,1900,2000,2049,
            2121,2181,2375,2376,3128,3306,3389,3500,3541,3689,4000,4040,4063,4333,4369,4443,4488,4500,4567,4899,
            5000,5001,5004,5006,5007,5008,5009,5060,5104,5222,5223,5269,5351,5353,5432,5555,5601,5632,5800,5801,
            5900,5901,5938,5984,5999,6000,6001,6379,6443,6588,6665,6666,6667,6668,6669,7001,7002,7077,7443,7574,
            8000,8001,8008,8010,8080,8081,8082,8086,8088,8090,8091,8181,8443,8484,8600,8649,8686,8787,8888,9000,
            9001,9002,9003,9009,9042,9050,9071,9080,9090,9091,9200,9300,9418,9443,9600,9800,9871,9999,10000,11211,
            12345,15672,16010,16080,16384,27017,27018,50050}
    } else {
        for _, item := range strings.Split(portRange, ",") {
            if strings.Contains(item, "-") {
                rangeParts := strings.Split(item, "-")
                startPort, _ := strconv.Atoi(rangeParts[0])
                endPort, _ := strconv.Atoi(rangeParts[1])
                for i := startPort; i <= endPort; i++ {
                    ports = append(ports, i)
                }
            } else {
                port, _ := strconv.Atoi(item)
                ports = append(ports, port)
            }
        }
    }
    return ports
}

func scanNetwork(network string, portRange string, timeout time.Duration, maxWorkers int, verbose bool) []map[string][]int {
    var results []map[string][]int
    hosts, err := hostsInNetwork(network)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return results
    }
    ch := make(chan string, maxWorkers)
    workerResultsCh := make(chan map[string][]int, len(hosts))
    ports := parsePorts(portRange)
    results = make([]map[string][]int, len(hosts))
    for i := 0; i < maxWorkers; i++ {
        go func() {
            for host := range ch {
                openPorts := scanHost(host, ports, timeout, verbose)
                if len(openPorts) > 0 {
                    result := make(map[string][]int)
                    result[host] = openPorts
                    workerResultsCh <- result
                } else {
                    workerResultsCh <- nil
                }
            }
        }()
    }
    for _, host := range hosts {
        ch <- host
    }
    close(ch)
    for i := 0; i < len(hosts); i++ {
        result := <-workerResultsCh
        if result != nil {
            results[i] = result
        }
    }
    return results
}

func hostsInNetwork(network string) ([]string, error) {
    ips := []string{}
    ip, ipNet, err := net.ParseCIDR(network)
    if err != nil {
        return ips, err
    }
    for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
        ips = append(ips, ip.String())
    }
    lenIps := len(ips)
    switch {
    case lenIps == 0:
        return ips, fmt.Errorf("no IP addresses found in network")
    default:
        return ips, nil
    }
}

func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

var (
    network   string
    portRange string
    timeout   int
    maxWorkers int
    verbose   bool
)

func init() {
    flag.StringVar(&network, "n", "", "Network to scan (e.g. \"192.168.0.1\" or \"192.168.0.0/24\")")
    flag.StringVar(&portRange, "p", "", "Ports to scan (e.g. \"80\" or \"1-65535\")")
    flag.IntVar(&timeout, "t", 500, "TCP connection timeout in milliseconds")
    flag.IntVar(&maxWorkers, "w", 100, "Maximum number of worker threads for the scan")
    flag.BoolVar(&verbose, "v", false, "Verbose output")
}

func main() {
    flag.Parse()

    if network == "" {
        fmt.Println("Please specify a network to scan")
        return
    }
    timeoutDuration := time.Duration(timeout) * time.Millisecond

    start := time.Now()
    fmt.Printf("[*] Scanning network %s (%s)...\n", network, portRange)
    results := scanNetwork(network, portRange, timeoutDuration, maxWorkers, verbose)
    elapsed := time.Since(start)

    if len(results) > 0 {
        fmt.Printf("[+] Found open ports on %d host(s):\n", len(results))
        for _, result := range results {
            for host, openPorts := range result {
                fmt.Printf("    %s: %v\n", host, openPorts)
            }
        }
    } else {
        fmt.Println("[-] No open ports found on any host.")
    }
    fmt.Printf("[+] Scan completed in %v.\n", elapsed)
}
