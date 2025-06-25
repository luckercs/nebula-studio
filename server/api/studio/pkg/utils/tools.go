package utils

import (
	"net"
	"os"
)

func Contains[T comparable](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func GetAllIPAddresses() ([]string, error) {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
			ips = append(ips, ip.String())
		}
	}

	return ips, nil
}

func GetHostname() (string, error) {
	return os.Hostname()
}