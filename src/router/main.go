package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"github.com/glasnostic/example/router/driver"
	"github.com/glasnostic/example/router/packet/handler"
)

var (
	nicName    string
	driverName string
	local      net.IP
	localMac   net.HardwareAddr
	client     net.IP
	server     net.IP
)

const (
	defaultDriver = "afxdp"
)

func main() {
	log.Println("===== Example setup =====")
	setup()
	log.Println("===== Example start =====")

	drv, err := driver.New(driverName, nicName)
	mustSuccess(err, "Failed to create driver with error")
	hdl := handler.NewRewriter(localMac, local, client, server)

	log.Println("======= Start running driver =======")
	go drv.Run(hdl)

	// Terminate _Example_ when receiving SIGINT | SIGTERM
	sig := make(chan os.Signal)
	signal.Notify(sig, unix.SIGINT, unix.SIGTERM)
	<-sig
	log.Println("====== Example end ======")
}

func setup() {
	routerIPString := os.Getenv("ROUTER")
	local = net.ParseIP(routerIPString)
	mustHaveIP(local, "local ip")

	clientIPString := os.Getenv("CLIENT")
	client = net.ParseIP(clientIPString)
	mustHaveIP(client, "client ip")

	serverIPString := os.Getenv("SERVER")
	server = net.ParseIP(serverIPString)
	mustHaveIP(server, "server ip")

	driverName := os.Getenv("DRIVER")
	if driverName == "" {
		driverName = defaultDriver
	}

	nicName = "eth0"
	mustSuccess(loadMAC(), "Failed to load local MAC")
	mustSuccess(setRlimit(), "Failed to setrlimit")

}

func loadMAC() error {
	// get localIP and mac
	nic, err := net.InterfaceByName(nicName)
	if err != nil {
		return fmt.Errorf("given NIC %s must existing and accessible", nicName)
	}
	localMac = nic.HardwareAddr
	return nil
}

func setRlimit() error {
	rLimit := &unix.Rlimit{
		Max: unix.RLIM_INFINITY,
		Cur: unix.RLIM_INFINITY,
	}
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, rLimit)
}

func mustSuccess(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func mustHaveIP(ip net.IP, msg string) {
	if ip == nil {
		log.Fatalf("%s must be given but missing!\n", msg)
	}

}
