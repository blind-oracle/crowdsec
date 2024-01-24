package socket

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type SocketConfiguration struct {
	Proto         string `yaml:"protocol,omitempty"`
	Addr          string `yaml:"listen_addr,omitempty"`
	MaxMessageLen int    `yaml:"max_message_len,omitempty"`
	Threads       int    `yaml:"threads,omitempty"`
	Buffer        int    `yaml:"buffer,omitempty"`

	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type SocketSource struct {
	config     SocketConfiguration
	logger     *log.Entry
	server     *Server
	serverTomb *tomb.Tomb
}

var packetsReceived = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "cs_socketsource_hits_total",
		Help: "Total packets that were received.",
	})

var bytesReceived = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "cs_socketsource_bytes_total",
		Help: "Total bytes that were received.",
	})

func (s *SocketSource) GetUuid() string {
	return s.config.UniqueId
}

func (s *SocketSource) GetName() string {
	return "syslog"
}

func (s *SocketSource) GetMode() string {
	return s.config.Mode
}

func (s *SocketSource) Dump() interface{} {
	return s
}

func (s *SocketSource) CanRun() error {
	return nil
}

func (s *SocketSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{packetsReceived, bytesReceived}
}

func (s *SocketSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{packetsReceived, bytesReceived}
}

func (s *SocketSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
}

func (s *SocketSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("syslog datasource does not support one shot acquisition")
}

func (s *SocketSource) UnmarshalConfig(yamlConfig []byte) error {
	s.config = SocketConfiguration{}
	s.config.Mode = configuration.TAIL_MODE

	err := yaml.UnmarshalStrict(yamlConfig, &s.config)
	if err != nil {
		return fmt.Errorf("cannot parse syslog configuration: %w", err)
	}

	if s.config.Proto == "" {
		s.config.Proto = "udp4"
	}

	if s.config.Addr == "" {
		s.config.Addr = "127.0.0.1:4242"
	}

	if s.config.MaxMessageLen == 0 {
		s.config.MaxMessageLen = 4096
	}

	if s.config.Buffer == 0 {
		s.config.Buffer = 32768
	}

	if s.config.Threads == 0 {
		s.config.Threads = 4
	}

	return nil
}

func (s *SocketSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	s.logger = logger
	s.logger.Infof("Starting syslog datasource configuration")

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
}

func (s *SocketSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	in := make(chan string)

	s.server = &Server{
		channel:       in,
		Logger:        s.logger.WithField("socket", "internal"),
		MaxMessageLen: s.config.MaxMessageLen,
	}

	err := s.server.Listen(s.config.Proto, s.config.Addr)
	if err != nil {
		return fmt.Errorf("could not start syslog server: %w", err)
	}

	s.serverTomb = s.server.StartServer()

	for i := 0; i < s.config.Threads; i++ {
		t.Go(func() error {
			defer trace.CatchPanic("crowdsec/acquis/syslog/live")
			return s.handlePacket(t, in, out)
		})
	}

	return nil
}

func (s *SocketSource) handlePacket(t *tomb.Tomb, in chan string, out chan types.Event) error {
	killed := false

	for {
		select {
		case <-t.Dying():
			if !killed {
				s.logger.Info("Syslog datasource is dying")
				s.serverTomb.Kill(nil)
				killed = true
			}

		case <-s.serverTomb.Dead():
			s.logger.Info("Syslog server has exited")
			return nil

		case p := <-in:
			l := types.Line{
				Raw:     p,
				Module:  s.GetName(),
				Labels:  s.config.Labels,
				Process: true,
			}

			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
		}
	}
}
