package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

type EncryptedSocks5 struct {
	*Base
	option *EncryptedSocks5Option
	user   string
	pass   string
}

type EncryptedSocks5Option struct {
	BasicOption
	Name      string `proxy:"name"`
	Server    string `proxy:"server"`
	Port      int    `proxy:"port"`
	Password  string `proxy:"password"`
	UserName  string `proxy:"username,omitempty"`
	SocksPass string `proxy:"socks-password,omitempty"`
	UDP       bool   `proxy:"udp,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter.
func (es *EncryptedSocks5) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c = newWheelConn(c)

	var user *socks5.User
	if es.user != "" {
		user = &socks5.User{
			Username: es.user,
			Password: es.pass,
		}
	}
	if _, err := es.clientHandshakeContext(ctx, c, serializesSocksAddr(metadata), socks5.CmdConnect, user); err != nil {
		return nil, err
	}
	return c, nil
}

// DialContext implements C.ProxyAdapter.
func (es *EncryptedSocks5) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := es.dialer.DialContext(ctx, "tcp", es.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", es.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = es.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, es), nil
}

// ListenPacketContext implements C.ProxyAdapter.
func (es *EncryptedSocks5) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = es.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	c, err := es.dialer.DialContext(ctx, "tcp", es.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", es.addr, err)
	}
	c = newWheelConn(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	var user *socks5.User
	if es.user != "" {
		user = &socks5.User{
			Username: es.user,
			Password: es.pass,
		}
	}

	udpAssociateAddr := socks5.AddrFromStdAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	bindAddr, err := es.clientHandshakeContext(ctx, c, udpAssociateAddr, socks5.CmdUDPAssociate, user)
	if err != nil {
		return nil, fmt.Errorf("client handshake error: %w", err)
	}

	bindUDPAddr := bindAddr.UDPAddr()
	if bindUDPAddr == nil {
		return nil, errors.New("invalid UDP bind address")
	}
	if bindUDPAddr.IP.IsUnspecified() {
		serverAddr, err := resolveUDPAddr(ctx, "udp", es.Addr(), C.IPv4Prefer)
		if err != nil {
			return nil, err
		}
		bindUDPAddr.IP = serverAddr.IP
	}

	pc, err := es.dialer.ListenPacket(ctx, "udp", "", bindUDPAddr.AddrPort())
	if err != nil {
		return nil, err
	}

	go func() {
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
		_ = pc.Close()
	}()

	return newPacketConn(&encryptedSocksPacketConn{PacketConn: pc, rAddr: bindUDPAddr, tcpConn: c}, es), nil
}

// ProxyInfo implements C.ProxyAdapter.
func (es *EncryptedSocks5) ProxyInfo() C.ProxyInfo {
	info := es.Base.ProxyInfo()
	info.DialerProxy = es.option.DialerProxy
	return info
}

func (es *EncryptedSocks5) clientHandshakeContext(ctx context.Context, c net.Conn, addr socks5.Addr, command socks5.Command, user *socks5.User) (_ socks5.Addr, err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	return socks5.ClientHandshake(c, addr, command, user)
}

func NewEncryptedSocks5(option EncryptedSocks5Option) (*EncryptedSocks5, error) {
	outbound := &EncryptedSocks5{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.EncryptedSocks5,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		user:   option.UserName,
		pass:   option.SocksPass,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

type encryptedSocksPacketConn struct {
	net.PacketConn
	rAddr   net.Addr
	tcpConn net.Conn
}

func (pc *encryptedSocksPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return 0, err
	}
	encryptWheel(packet)
	n, err := pc.PacketConn.WriteTo(packet, pc.rAddr)
	if err != nil {
		return 0, err
	}
	if n < len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (pc *encryptedSocksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	decryptWheel(b[:n])

	addr, payload, err := socks5.DecodeUDPPacket(b[:n])
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse udp addr error")
	}

	copy(b, payload)
	return len(payload), udpAddr, nil
}

func (pc *encryptedSocksPacketConn) Close() error {
	_ = pc.tcpConn.Close()
	return pc.PacketConn.Close()
}

type wheelConn struct {
	net.Conn
}

func newWheelConn(c net.Conn) net.Conn {
	return &wheelConn{Conn: c}
}

func (c *wheelConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	decryptWheel(b[:n])
	return n, err
}

func (c *wheelConn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	encryptWheel(buf)
	return c.Conn.Write(buf)
}

func encryptWheel(b []byte) {
	for i := range b {
		b[i] = encryptedSocks5EncryptWheel[b[i]]
	}
}

func decryptWheel(b []byte) {
	for i := range b {
		b[i] = encryptedSocks5DecryptWheel[b[i]]
	}
}
