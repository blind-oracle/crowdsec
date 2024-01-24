package socket

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type Server struct {
	channel       chan string
	conn          net.PacketConn
	Logger        *log.Entry
	MaxMessageLen int
}

func (s *Server) Listen(network, address string) error {
	var err error
	s.conn, err = net.ListenPacket(network, address)
	if err != nil {
		return fmt.Errorf("unable to listen on %s %s: %w", network, address, err)
	}

	return nil
}

func (s *Server) StartServer() *tomb.Tomb {
	t := tomb.Tomb{}
	buf := make([]byte, s.MaxMessageLen)

	t.Go(func() error {
		for {
			select {
			case <-t.Dying():
				s.Logger.Info("Syslog server tomb is dying")
				err := s.KillServer()
				return err

			default:
				n, _, err := s.conn.ReadFrom(buf)
				if err != nil {
					s.Logger.Errorf("error while reading from socket : %s", err)
					s.conn.Close()
					return err
				}

				packetsReceived.Inc()
				bytesReceived.Add(float64(n))
				raw := string(buf[:n])

				s.Logger.Tracef("raw: %s", raw)
				s.channel <- raw
			}
		}
	})

	return &t
}

func (s *Server) KillServer() error {
	err := s.conn.Close()
	if err != nil {
		return fmt.Errorf("could not close connection: %w", err)
	}

	close(s.channel)
	return nil
}
