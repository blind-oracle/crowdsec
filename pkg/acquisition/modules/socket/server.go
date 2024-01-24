package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type Server struct {
	channel       chan string
	conn          net.PacketConn
	listener      net.Listener
	Logger        *log.Entry
	MaxMessageLen int
}

func (s *Server) Listen(network, address string) error {
	if strings.HasPrefix(network, "unix") {
		_ = os.Remove(address)
	}

	var err error
	if strings.HasPrefix(network, "tcp") || network == "unix" {
		s.listener, err = net.Listen(network, address)
		if err != nil {
			return fmt.Errorf("unable to listen on %s %s: %w", network, address, err)
		}
	} else if strings.HasPrefix(network, "udp") || network == "unixgram" {
		s.conn, err = net.ListenPacket(network, address)
		if err != nil {
			return fmt.Errorf("unable to listen on %s %s: %w", network, address, err)
		}
	} else {
		return fmt.Errorf("unsupported network type: %s", network)
	}

	if network == "unix" {
		if err = os.Chmod(address, 0o666); err != nil {
			return fmt.Errorf("chmod %s failed: %w", address, err)
		}
	}

	s.Logger.Infof("Listening on %s:%s", network, address)
	return nil
}

func (s *Server) StartServer() *tomb.Tomb {
	t := tomb.Tomb{}

	if s.conn != nil {
		t.Go(func() error { return s.LoopDeadline(&t) })
		t.Go(func() error { return s.LoopPacket(&t) })
	} else {
		t.Go(func() error { return s.LoopStream(&t) })
	}

	return &t
}

func (s *Server) LoopDeadline(t *tomb.Tomb) error {
	ticker := time.NewTicker(500 * time.Millisecond)

	for {
		select {
		case <-t.Dying():
			return nil

		case <-ticker.C:
			s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}
	}
}

func (s *Server) LoopStream(t *tomb.Tomb) error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			s.Logger.Errorf("Error in Accept(): %s", err)
			time.Sleep(time.Second)
			continue
		}

		t.Go(func() error { return s.HandleConnection(conn, t) })
	}
}

func (s *Server) HandleConnection(c net.Conn, t *tomb.Tomb) error {
	var l uint32
	buf := make([]byte, s.MaxMessageLen)

	for {
		select {
		case <-t.Dying():
			return nil

		default:
			// Slice back to max
			buf = buf[:s.MaxMessageLen]

			// Read length
			err := binary.Read(c, binary.BigEndian, &l)
			if err != nil {
				if err == io.EOF {
					return nil
				}

				s.Logger.Errorf("Error in Read(): %s", err)
				c.Close()
				return err
			}

			if l > uint32(s.MaxMessageLen) {
				c.Close()
				err = fmt.Errorf("too big message length (%d > %d), closing", l, s.MaxMessageLen)
				s.Logger.Error(err.Error())
				return err
			}

			// Slice to msg len
			buf = buf[:l]
			if _, err = io.ReadFull(c, buf); err != nil {
				if err == io.EOF {
					return nil
				}

				s.Logger.Errorf("Error in Read(): %s", err)
				c.Close()
				return err
			}

			raw := string(buf)
			s.Logger.Tracef("raw: %s", raw)
			s.channel <- raw
		}
	}
}

func (s *Server) LoopPacket(t *tomb.Tomb) error {
	buf := make([]byte, s.MaxMessageLen)

	for {
		select {
		case <-t.Dying():
			return nil

		default:
			n, _, err := s.conn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}

				if os.IsTimeout(err) {
					s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					continue
				}

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
}

func (s *Server) Close() error {
	if s.conn != nil {
		_ = s.conn.Close()
	} else {
		s.listener.Close()
	}

	return nil
}
