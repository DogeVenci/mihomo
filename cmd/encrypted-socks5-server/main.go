package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	socksVersion5 = 0x05

	methodNoAuth       = 0x00
	methodUserPassword = 0x02
	methodNoAcceptable = 0xff

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySucceeded          = 0x00
	replyGeneralFailure     = 0x01
	replyCommandUnsupported = 0x07
	replyAddressUnsupported = 0x08
)

type server struct {
	listenAddr string
	username   string
	password   string
	udpTimeout time.Duration
}

type socksRequest struct {
	command byte
	address string
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:1081", "encrypted socks5 listen address")
	password := flag.String("password", "demo-secret", "ignored; kept for compatibility with earlier tests")
	username := flag.String("username", "", "optional SOCKS5 username")
	socksPassword := flag.String("socks-password", "", "optional SOCKS5 password")
	udpTimeout := flag.Duration("udp-timeout", 10*time.Second, "UDP response timeout")
	flag.Parse()

	_ = password

	s := &server{
		listenAddr: *listenAddr,
		username:   *username,
		password:   *socksPassword,
		udpTimeout: *udpTimeout,
	}
	if err := s.serve(); err != nil {
		log.Fatal(err)
	}
}

func (s *server) serve() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.listenAddr, err)
	}
	defer ln.Close()

	log.Printf("encrypted-socks5 server listening on %s", s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *server) handleConn(rawClient net.Conn) {
	defer rawClient.Close()

	client := newWheelConn(rawClient)
	req, err := socksHandshake(client, s.username, s.password)
	if err != nil {
		log.Printf("socks handshake from %s: %v", rawClient.RemoteAddr(), err)
		return
	}

	switch req.command {
	case cmdConnect:
		s.handleConnect(client, rawClient.RemoteAddr(), req.address)
	case cmdUDPAssociate:
		s.handleUDPAssociate(client, rawClient.RemoteAddr())
	default:
		_ = writeReply(client, replyCommandUnsupported, nil)
	}
}

func (s *server) handleConnect(client net.Conn, clientAddr net.Addr, targetAddr string) {
	target, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		_ = writeReply(client, replyGeneralFailure, nil)
		log.Printf("dial target %s: %v", targetAddr, err)
		return
	}
	defer target.Close()

	if err := writeReply(client, replySucceeded, target.LocalAddr()); err != nil {
		log.Printf("write reply to %s: %v", clientAddr, err)
		return
	}

	log.Printf("tcp proxy %s -> %s", clientAddr, targetAddr)
	relay(client, target)
}

func (s *server) handleUDPAssociate(client net.Conn, clientAddr net.Addr) {
	udpConn, err := net.ListenPacket("udp", s.listenAddr)
	if err != nil {
		_ = writeReply(client, replyGeneralFailure, nil)
		log.Printf("udp listen: %v", err)
		return
	}
	defer udpConn.Close()

	if err := writeReply(client, replySucceeded, udpConn.LocalAddr()); err != nil {
		log.Printf("write UDP associate reply to %s: %v", clientAddr, err)
		return
	}

	log.Printf("udp associate %s -> %s", clientAddr, udpConn.LocalAddr())
	done := make(chan struct{})
	go s.serveUDPAssociation(udpConn, done)

	_, _ = io.Copy(io.Discard, client)
	close(done)
}

func (s *server) serveUDPAssociation(pc net.PacketConn, done <-chan struct{}) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-done:
			return
		default:
		}

		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("udp read: %v", err)
			return
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		go s.handleUDPPacket(pc, clientAddr, packet)
	}
}

func (s *server) handleUDPPacket(pc net.PacketConn, clientAddr net.Addr, packet []byte) {
	decryptWheel(packet)

	targetAddr, payload, err := decodeUDPRequest(packet)
	if err != nil {
		log.Printf("udp decode from %s: %v", clientAddr, err)
		return
	}

	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		log.Printf("resolve udp target %s: %v", targetAddr, err)
		return
	}

	target, err := net.DialUDP("udp", nil, targetUDPAddr)
	if err != nil {
		log.Printf("dial udp target %s: %v", targetAddr, err)
		return
	}
	defer target.Close()

	if _, err := target.Write(payload); err != nil {
		log.Printf("write udp target %s: %v", targetAddr, err)
		return
	}

	_ = target.SetReadDeadline(time.Now().Add(s.udpTimeout))
	response := make([]byte, 64*1024)
	n, responseAddr, err := target.ReadFromUDP(response)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return
		}
		log.Printf("read udp target %s: %v", targetAddr, err)
		return
	}

	reply, err := encodeUDPResponse(responseAddr, response[:n])
	if err != nil {
		log.Printf("encode udp response from %s: %v", responseAddr, err)
		return
	}
	encryptWheel(reply)

	if _, err := pc.WriteTo(reply, clientAddr); err != nil {
		log.Printf("write udp client %s: %v", clientAddr, err)
	}
}

func socksHandshake(conn net.Conn, username, password string) (*socksRequest, error) {
	if err := negotiateMethod(conn, username, password); err != nil {
		return nil, err
	}
	return readRequest(conn)
}

func negotiateMethod(conn net.Conn, username, password string) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("unsupported socks version: %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	requireAuth := username != "" || password != ""
	method := byte(methodNoAcceptable)
	for _, candidate := range methods {
		if requireAuth && candidate == methodUserPassword {
			method = methodUserPassword
			break
		}
		if !requireAuth && candidate == methodNoAuth {
			method = methodNoAuth
			break
		}
	}

	if _, err := conn.Write([]byte{socksVersion5, method}); err != nil {
		return err
	}
	if method == methodNoAcceptable {
		return errors.New("no acceptable auth method")
	}
	if method == methodUserPassword {
		return authenticateUserPassword(conn, username, password)
	}
	return nil
}

func authenticateUserPassword(conn net.Conn, username, password string) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return fmt.Errorf("unsupported username/password auth version: %d", header[0])
	}

	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}

	passLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return err
	}
	pass := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(user) != username || string(pass) != password {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("invalid username/password")
	}

	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readRequest(conn net.Conn) (*socksRequest, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != socksVersion5 {
		return nil, fmt.Errorf("unsupported request version: %d", header[0])
	}
	if header[1] != cmdConnect && header[1] != cmdUDPAssociate {
		return nil, fmt.Errorf("unsupported command: %d", header[1])
	}

	host, err := readAddress(conn, header[3])
	if err != nil {
		_ = writeReply(conn, replyAddressUnsupported, nil)
		return nil, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return &socksRequest{
		command: header[1],
		address: net.JoinHostPort(host, strconv.Itoa(int(port))),
	}, nil
}

func readAddress(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		ip := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil
	case atypIPv6:
		ip := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func writeReply(conn net.Conn, reply byte, bindAddr net.Addr) error {
	host := net.IPv4zero
	port := 0

	switch addr := bindAddr.(type) {
	case *net.TCPAddr:
		host = addr.IP
		port = addr.Port
	case *net.UDPAddr:
		host = addr.IP
		port = addr.Port
	}

	if ip4 := host.To4(); ip4 != nil {
		buf := []byte{socksVersion5, reply, 0x00, atypIPv4, ip4[0], ip4[1], ip4[2], ip4[3], 0x00, 0x00}
		binary.BigEndian.PutUint16(buf[8:], uint16(port))
		_, err := conn.Write(buf)
		return err
	}

	ip16 := host.To16()
	if ip16 == nil {
		ip16 = net.IPv6zero
	}
	buf := make([]byte, 4+net.IPv6len+2)
	buf[0], buf[1], buf[2], buf[3] = socksVersion5, reply, 0x00, atypIPv6
	copy(buf[4:], ip16)
	binary.BigEndian.PutUint16(buf[4+net.IPv6len:], uint16(port))
	_, err := conn.Write(buf)
	return err
}

func decodeUDPRequest(packet []byte) (string, []byte, error) {
	if len(packet) < 5 {
		return "", nil, errors.New("short UDP packet")
	}
	if packet[0] != 0 || packet[1] != 0 {
		return "", nil, errors.New("invalid UDP reserved field")
	}
	if packet[2] != 0 {
		return "", nil, errors.New("fragmented UDP packet is not supported")
	}

	host, addrLen, err := parseAddr(packet[3:])
	if err != nil {
		return "", nil, err
	}
	return host, packet[3+addrLen:], nil
}

func parseAddr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, errors.New("missing address type")
	}

	switch b[0] {
	case atypIPv4:
		const addrLen = 1 + net.IPv4len + 2
		if len(b) < addrLen {
			return "", 0, errors.New("short IPv4 address")
		}
		host := net.IP(b[1 : 1+net.IPv4len]).String()
		port := binary.BigEndian.Uint16(b[1+net.IPv4len:])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), addrLen, nil
	case atypIPv6:
		const addrLen = 1 + net.IPv6len + 2
		if len(b) < addrLen {
			return "", 0, errors.New("short IPv6 address")
		}
		host := net.IP(b[1 : 1+net.IPv6len]).String()
		port := binary.BigEndian.Uint16(b[1+net.IPv6len:])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), addrLen, nil
	case atypDomain:
		if len(b) < 2 {
			return "", 0, errors.New("short domain address")
		}
		domainLen := int(b[1])
		addrLen := 1 + 1 + domainLen + 2
		if len(b) < addrLen {
			return "", 0, errors.New("short domain payload")
		}
		host := string(b[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(b[2+domainLen:])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), addrLen, nil
	default:
		return "", 0, fmt.Errorf("unsupported address type: %d", b[0])
	}
}

func encodeUDPResponse(addr *net.UDPAddr, payload []byte) ([]byte, error) {
	if addr == nil {
		return nil, errors.New("nil UDP address")
	}

	var socksAddr []byte
	if ip4 := addr.IP.To4(); ip4 != nil {
		socksAddr = []byte{atypIPv4, ip4[0], ip4[1], ip4[2], ip4[3], 0x00, 0x00}
		binary.BigEndian.PutUint16(socksAddr[5:], uint16(addr.Port))
	} else {
		ip16 := addr.IP.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("invalid UDP address: %s", addr)
		}
		socksAddr = make([]byte, 1+net.IPv6len+2)
		socksAddr[0] = atypIPv6
		copy(socksAddr[1:], ip16)
		binary.BigEndian.PutUint16(socksAddr[1+net.IPv6len:], uint16(addr.Port))
	}

	packet := make([]byte, 3+len(socksAddr)+len(payload))
	copy(packet[3:], socksAddr)
	copy(packet[3+len(socksAddr):], payload)
	return packet, nil
}

func relay(client, target net.Conn) {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(target, client)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(client, target)
		errCh <- err
	}()

	if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("relay: %v", err)
	}
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

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: encrypted-socks5-server [options]\n\n")
		flag.PrintDefaults()
	}
}
