package services

import (
	"golang.org/x/sys/windows/svc"
	"log"
)

type DDNSService struct {
	handler func()
}

func (service *DDNSService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	defer func() {
		changes <- svc.Status{State: svc.StopPending}
		log.Println("Shutting down")
	}()

	go service.handler()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Println("Startup complete")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected services control request #%d\n", c)
			}
		}
	}
}

func Run(serviceName string, handler func()) error {
	return svc.Run(serviceName, &DDNSService{handler: handler})
}
