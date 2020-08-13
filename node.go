package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/oasisprotocol/ed25519"
	"go.uber.org/atomic"
	"go.uber.org/zap"
)

// Node keeps track of a users ID, all of a users outgoing/incoming connections to/from peers as *Client instances
// under a bounded connection pool whose bounds may be configured, the TCP listener which accepts new incoming peer
// connections, and all Go types that may be serialized/deserialized at will on-the-wire or through a Handler.
//
// A node at most will only have one goroutine + num configured worker goroutines associated to it which represents
// the listener looking to accept new incoming peer connections, and workers responsible for handling incoming peer
// messages. A node once closed or once started (as in, (*Node).Listen was called) should not be reused.
type Node struct {
	logger *zap.Logger

	host net.IP
	port uint16
	addr string

	publicKey  PublicKey
	privateKey PrivateKey

	id ID

	maxDialAttempts        uint
	maxInboundConnections  uint
	maxOutboundConnections uint
	maxRecvMessageSize     uint32
	numWorkers             uint

	idleTimeout time.Duration

	listener  net.Listener
	listening atomic.Bool

	outbound *clientMap
	inbound  *clientMap

	codec     *codec
	protocols []Protocol
	handlers  []Handler

	workers sync.WaitGroup
	work    chan HandlerContext

	listenerDone chan error
}

// NewNode instantiates a new node instance, and pre-configures the node with provided options.
// Default values for some non-specified options are instantiated as well, which may yield an error.
func NewNode(opts ...NodeOption) (*Node, error) {
	n := &Node{
		listenerDone: make(chan error, 1),

		maxDialAttempts:        3,
		maxInboundConnections:  128,
		maxOutboundConnections: 128,
		maxRecvMessageSize:     4 << 20,
		numWorkers:             uint(runtime.NumCPU()),
	}

	for _, opt := range opts {
		opt(n)
	}

	if n.logger == nil {
		n.logger = zap.NewNop()
	}

	if n.privateKey == ZeroPrivateKey {
		_, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}

		copy(n.privateKey[:], privateKey)
	}

	copy(n.publicKey[:], ed25519.PrivateKey(n.privateKey[:]).Public().(ed25519.PublicKey)[:])

	if n.id.ID == ZeroPublicKey && n.host != nil && n.port > 0 {
		n.id = NewID(n.publicKey, n.host, n.port)
	}

	n.inbound = newClientMap(n.maxInboundConnections)
	n.outbound = newClientMap(n.maxOutboundConnections)

	n.codec = newCodec()

	return n, nil
}

// Listen has the node start listening for new peers. If an error occurs while starting the listener due to
// misconfigured options or resource exhaustion, an error is returned. If the node is already listening
// for new connections, an error is thrown.
//
// Listen must not be called concurrently, and should only ever be called once per node instance.
func (n *Node) Listen() error {
	if n.listening.Load() {
		return errors.New("node is already listenintg")
	}

	var err error
	defer func() {
		if err != nil {
			n.listening.Store(false)
		}
	}()

	n.listener, err = net.Listen("tcp", net.JoinHostPort(normalizeIP(n.host), strconv.FormatUint(uint64(n.port), 10)))
	if err != nil {
		return err
	}

	addr, ok := n.listener.Addr().(*net.TCPAddr)
	if !ok {
		n.listener.Close()
		return errors.New("Did not bind to TCP address")
	}

	n.host = addr.IP
	n.port = uint16(addr.Port)

	if n.addr == "" {
		n.addr = net.JoinHostPort(normalizeIP(n.host), strconv.FormatUint(uint64(n.port), 10))
		n.id = NewID(n.publicKey, n.host, n.port)
	} else {
		resolved, err := ResolveAddress(n.addr)
		if err != nil {
			n.listener.Close()
			return err
		}

		hostStr, portStr, err := net.SplitHostPort(resolved)
		if err != nil {
			n.listener.Close()
			return err
		}

		host := net.ParseIP(hostStr)
		if host == nil {
			n.listener.Close()
			return errors.New("Host in provided public address is invalid(must be IPv4/IPv6)")
		}

		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			n.listener.Close()
			return err
		}

		n.id = NewID(n.publicKey, host, uint16(port))
	}

	for _, protocol := range n.protocols {
		if protocol.Bind == nil {
			continue
		}

		if err = protocol.Bind(n); err != nil {
			n.listener.Close()
			return err
		}
	}

	n.work = make(chan HandlerContext, int(n.numWorkers))
	n.workers.Add(int(n.numWorkers))

	for i := uint(0); i < n.numWorkers; i++ {
		go func() {
			defer n.workers.Done()
			for ctx := range n.work {
				for _, handler := range n.handlers {
					if err := handler(ctx); err != nil {
						ctx.client.Logger().Warn("Got an error executing a message handeler.", zap.Error(err))
						ctx.client.reportError(err)
						ctx.client.close()

						return
					}
				}
			}
		}()
	}

	go func() {
		n.listening.Store(true)

		defer func() {
			n.inbound.release()

			close(n.work)
			n.workers.Wait()

			n.listening.Store(false)
			close(n.listenerDone)
		}()

		n.logger.Info("Listening for incoming peers.",
			zap.String("bind_addr", addr.String()),
			zap.String("ip_addr", n.id.Address),
			zap.String("public_key", n.publicKey.String()),
			zap.String("private_key", n.privateKey.String()),
		)

		for {
			conn, err := n.listener.Accept()
			if err != nil {
				n.listenerDone <- err
				break
			}

			addr := conn.RemoteAddr().String()

			client, exists := n.inbound.get(n, addr)
			if !exists {
				go client.inbound(conn, addr)
			}
		}
	}()

	return nil
}

// RegisterMessage registers a Go type T that implements the Serializable interface with an associated deserialize
// function whose sigature comprises of func([]byte) (T, error). It retirns a 16bit unsigned ineteger(opcode) associated
// to type T on the wire
func (n *Node) RegisterMessage(ser Serializable, de interface{}) uint16 {
	return n.codec.register(ser, de)
}

//EncodeMessage encodes msg which must be a registered go Type T into its wire representation
func (n *Node) EncodeMessage(msg Serializable) ([]byte, error) {
	return n.codec.encode(msg)
}

//DecodeMessage asd
func (n *Node) DecodeMessage(data []byte) (Serializable, error) {
	return n.codec.decode(data)
}

// SendMessage asd
func (n *Node) SendMessage(ctx context.Context, addr string, msg Serializable) error {
	data, err := n.EncodeMessage(msg)
	if err != nil {
		return err
	}

	return n.Send(ctx, addr, data)
}

//RequestMessage asd
func (n *Node) RequestMessage(ctx context.Context, addr string, req Serializable) (Serializable, error) {
	data, err := n.EncodeMessage(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	data, err = n.Request(ctx, addr, data)
	if err != nil {
		return nil, err
	}

	res, err := n.DecodeMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode request: %w", err)
	}

	return res, nil
}

//Send asd
func (n *Node) Send(ctx context.Context, addr string, data []byte) error {
	c, err := n.dialIfNotExists(ctx, addr)
	if err != nil {
		return err
	}

	if err := c.send(0, data); err != nil {
		return err
	}

	return nil
}

//Request asd
func (n *Node) Request(ctx context.Context, addr string, data []byte) ([]byte, error) {
	c, err := n.dialIfNotExists(ctx, addr)
	if err != nil {
		return nil, err
	}

	msg, err := c.request(ctx, data)
	if err != nil {
		return nil, err
	}

	return msg.data, nil
}

//Ping asd
func (n *Node) Ping(ctx context.Context, addr string) (*Client, error) {
	return n.dialIfNotExists(ctx, addr)
}

//Close asd
func (n *Node) Close() error {
	if n.listening.CAS(true, false) {
		if err := n.listener.Close(); err != nil {
			return err
		}
	}

	<-n.listenerDone
	return nil
}

//dialIfNotExists asd
func (n *Node) dialIfNotExists(ctx context.Context, addr string) (*Client, error) {
	var err error

	for i := uint(0); i < n.maxDialAttempts; i++ {
		client, exists := n.outbound.get(n, addr)
		if !exists {
			go client.outbound(ctx, addr)
		}

		select {
		case <-ctx.Done():
			err = fmt.Errorf("Failed ti dial peer: %w", ctx.Err())
		case <-client.ready:
			err = client.Error()
		case <-client.readerDone:
			err = client.Error()
		case <-client.writerDone:
			err = client.Error()
		}

		if err == nil {
			return client, nil
		}

		client.close()
		client.waitUntilClosed()

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			for _, protocol := range n.protocols {
				if protocol.OnPingFailed == nil {
					continue
				}
				protocol.OnPingFailed(addr, err)
			}
			return nil, err
		}
	}

	err = fmt.Errorf("attempted to dial %s several time but failed: %w", addr, err)

	for _, protocol := range n.protocols {
		if protocol.OnPingFailed == nil {
			continue
		}

		protocol.OnPingFailed(addr, err)
	}

	return nil, err
}

//Handle asd
func (n *Node) Handle(handlers ...Handler) {
	if n.listening.Load() {
		return
	}

	n.handlers = append(n.handlers, handlers...)
}

//Sign asd
func (n *Node) Sign(data []byte) Signature {
	return n.privateKey.Sign(data)
}

// Inbound asd
func (n *Node) Inbound() []*Client {
	return n.inbound.slice()
}

// Outbound asd
func (n *Node) Outbound() []*Client {
	return n.outbound.slice()
}

// Addr asd
func (n *Node) Addr() string {
	return n.addr
}

//Logger asd
func (n *Node) Logger() *zap.Logger {
	return n.logger
}

//ID asd
func (n *Node) ID() ID {
	return n.id
}
