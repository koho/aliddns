package main

import (
	"aliddns/ddns"
	"aliddns/services"
	"flag"
	"log"
	"os"
	"time"
)

var (
	ak         = flag.String("ak", "", "access key")
	sk         = flag.String("sk", "", "secret key")
	domain     = flag.String("d", "", "domain")
	recordType = flag.String("t", "A", "record type")
	line       = flag.String("l", "default", "line <default|telecom|unicom|mobile|oversea|edu|drpeng|btvn>")
	ttl        = flag.Int("ttl", 600, "TTL")
	source     = flag.String("s", "https://api64.ipify.org/", "IP source url (use interface address if it's empty)")
	ifName     = flag.String("if", "", "interface name")
	interval   = flag.Int("i", 300, "update interval(Seconds)")
	v6         = flag.Bool("6", false, "use IPv6")
	service    = flag.Bool("svc", false, "run as service")
	svcName    = flag.String("name", "", "service name")
	install    = flag.Bool("install", false, "install as service")
	remove     = flag.Bool("remove", false, "remove service")
)

func CheckAndUpdate() {
	hostRecord, topDomain := ddns.SplitDomain(*domain)
	var err error
	var ip string
	var descDomainParam ddns.DescribeDomainParameter
	var addDomainParam ddns.AddDomainParameter
	var updateDomainParam ddns.UpdateDomainParameter
	var record *ddns.DomainRecord
	for {
		ip, err = ddns.DetectIP(*source, *ifName, *v6)
		if err != nil {
			log.Println(err)
			goto sleep
		}
		log.Println("Detected IP address:", ip)
		descDomainParam = ddns.NewDescribeDomainParameter(*ak, *recordType, topDomain, hostRecord)
		record, err = ddns.QueryRecord(descDomainParam, *sk, *ifName)
		if err != nil {
			log.Println(err)
			goto sleep
		}
		if record == nil {
			addDomainParam = ddns.NewAddDomainParameter(*ak, *recordType, topDomain, hostRecord, ip, *line, *ttl)
			if err = ddns.AddRecord(addDomainParam, *sk, *ifName); err != nil {
				log.Println(err)
			}
			log.Printf("Added domain %s with value %s\n", *domain, ip)
			goto sleep
		}
		if ip == record.Value {
			goto sleep
		}
		updateDomainParam = ddns.NewUpdateDomainParameter(*ak, record.RecordId, *recordType, hostRecord, ip, *line, *ttl)
		if err = ddns.UpdateRecord(updateDomainParam, *sk, *ifName); err != nil {
			log.Println(err)
			goto sleep
		}
		log.Printf("Updated domain %s with value %s\n", *domain, ip)
	sleep:
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

func main() {
	flag.Parse()
	if *ak == "" || *sk == "" || *domain == "" {
		return
	}
	if *remove {
		if *svcName == "" {
			log.Fatal("empty service name")
		}
		if err := services.UninstallService(*svcName); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *install {
		if *svcName == "" {
			log.Fatal("empty service name")
		}
		args := make([]string, 0)
		for _, arg := range os.Args[1:] {
			if arg == "-install" || arg == "--install" {
				continue
			}
			args = append(args, arg)
		}
		args = append(args, "-svc")
		if err := services.InstallService(*svcName, args); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *service {
		if *svcName == "" {
			log.Fatal("empty service name")
		}
		services.Run(*svcName, CheckAndUpdate)
	} else {
		CheckAndUpdate()
	}
}
