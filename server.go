package swtpmproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/mdlayher/vsock"
)

const CMD_SET_DATAFD = 0x10
const TPM_SUCCESS = 0
const TPM_FAIL = 9

type BackendType int

const (
	BackendIP BackendType = iota
	BackendVsock
)

type ConnChannelProxy struct {
	backendConn io.ReadWriteCloser
	qemuConn    io.ReadWriteCloser
}

type TpmProxyChannels struct {
	controlChannel ConnChannelProxy
	dataChannel    ConnChannelProxy
}

type SwtpmProxyOptions struct {
	ControlSocketPath string // Path to the UNIX socket to listen on

	BackendType    BackendType // Type of backend connection (IP or Vsock)
	BackendAddress string      // Remote address to connect to
	BackendCid     uint32      // CID for vsock connections

	BackendControlPort uint16 // Port for backend control connection
	BackendDataPort    uint16 // Port for backend data connection
}

type SwtpmProxy struct {
	Options SwtpmProxyOptions
}

func NewStwpmProxy(options SwtpmProxyOptions) *SwtpmProxy {
	return &SwtpmProxy{
		Options: options,
	}
}

func isSetDataFdCmd(buf []byte) error {

	if len(buf) < 4 {
		return fmt.Errorf("buffer less than 4 bytes long short")
	}
	if binary.BigEndian.Uint32(buf) != CMD_SET_DATAFD {
		return fmt.Errorf("not a CMD_SET_DATAFD command, expected 0x10, got %x", binary.BigEndian.Uint32(buf))
	}
	return nil
}

func parseSetDataOob(buf []byte) (uint32, error) {
	if len(buf) == 0 {
		return 0, fmt.Errorf("no ancillary data received")
	}
	scmss, err := syscall.ParseSocketControlMessage(buf)
	if err != nil {
		return 0, fmt.Errorf("failed to parse socket control message: %w", err)
	}
	if len(scmss) != 1 {
		return 0, fmt.Errorf("expected exactly one socket control message, got: %d", len(scmss))
	}
	if scmss[0].Header.Type != syscall.SOL_SOCKET || scmss[0].Header.Level != syscall.SCM_RIGHTS {
		return 0, fmt.Errorf("expected SCM_RIGHTS socket control message, got: %d %d", scmss[0].Header.Type, scmss[0].Header.Level)
	}
	if scmss[0].Header.Len < 4 {
		return 0, fmt.Errorf("socket control message length too short: %d", scmss[0].Header.Len)
	}

	return binary.NativeEndian.Uint32(scmss[0].Data[:4]), nil
}

func (p *SwtpmProxy) handleQemuSetFd(backendControl io.ReadWriteCloser, qemuControl *net.UnixConn) (*TpmProxyChannels, error) {
	buf := make([]byte, 4096)
	oob := make([]byte, 4096)
	tpmResult := TPM_FAIL

	defer func() {
		res := make([]byte, 0, 4)
		res = binary.BigEndian.AppendUint32(res, uint32(tpmResult))
		qemuControl.Write(res)
	}()

	n, oobn, _, _, err := qemuControl.ReadMsgUnix(buf, oob)

	if err != nil {
		return nil, fmt.Errorf("failed to read from QEMU control socket: %w", err)
	}

	// The first messaged send by QEMU is the setfd command, if not we fail
	if err = isSetDataFdCmd(buf[:n]); err != nil {
		return nil, err
	}

	fd, err := parseSetDataOob(oob[:oobn])
	if err != nil {
		return nil, err
	}

	qemuDataChan := os.NewFile(uintptr(fd), "data_fd")
	if qemuDataChan == nil {
		return nil, fmt.Errorf("received an invalid file descriptor from qemu: %d", fd)
	}

	var backendDataConn io.ReadWriteCloser
	switch p.Options.BackendType {
	case BackendIP:
		backendDataConn, err = net.Dial("tcp", net.JoinHostPort(p.Options.BackendAddress, fmt.Sprintf("%d", p.Options.BackendDataPort)))
	case BackendVsock:
		backendDataConn, err = vsock.Dial(p.Options.BackendCid, uint32(p.Options.BackendDataPort), nil)
	default:
		err = fmt.Errorf("no backend data address specified")
	}
	if err != nil {
		qemuDataChan.Close()
		return nil, fmt.Errorf("failed dialing to backend data channel: %w", err)
	}

	tpmResult = TPM_SUCCESS
	return &TpmProxyChannels{
		controlChannel: ConnChannelProxy{
			backendConn: backendControl,
			qemuConn:    qemuControl,
		},
		dataChannel: ConnChannelProxy{
			backendConn: backendDataConn,
			qemuConn:    qemuDataChan,
		},
	}, nil
}

func (p *SwtpmProxy) Start() error {
	if _, err := os.Stat(p.Options.ControlSocketPath); err == nil {
		os.Remove(p.Options.ControlSocketPath)
	}

	l, err := net.Listen("unix", p.Options.ControlSocketPath)

	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", p.Options.ControlSocketPath, err)
	}

	defer l.Close()

	for {
		clientConn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept error: %w", err)
		}

		qemuControlConn, ok := clientConn.(*net.UnixConn)
		if !ok {
			clientConn.Close()
			continue
		}

		var swtpmControlConn io.ReadWriteCloser
		switch p.Options.BackendType {
		case BackendIP:
			swtpmControlConn, err = net.Dial("tcp", net.JoinHostPort(p.Options.BackendAddress, fmt.Sprintf("%d", p.Options.BackendControlPort)))
		case BackendVsock:
			swtpmControlConn, err = vsock.Dial(p.Options.BackendCid, uint32(p.Options.BackendControlPort), nil)
		default:
			err = fmt.Errorf("unsupported backend type")
		}
		if err != nil {
			clientConn.Close()
			return fmt.Errorf("failed dialing to backend control channel: %w", err)
		}
		fmt.Println("New connection established, handling QEMU setfd command...")

		chans, err := p.handleQemuSetFd(swtpmControlConn, qemuControlConn)

		if err != nil {
			fmt.Printf("Error handling QEMU setfd command: %v\n", err)
			swtpmControlConn.Close()
			qemuControlConn.Close()
		}

		// We don't want to handle multiple connections for the same vTPM instance, run this synchronously
		err = chans.Proxy()
		if err != nil {
			fmt.Printf("Error during proxying: %v\n", err)
		}
	}

}

func (p *TpmProxyChannels) Proxy() error {
	errCh := make(chan error, 1)

	proxy := func(dst io.WriteCloser, src io.ReadCloser) {
		_, err := io.Copy(dst, src)
		errCh <- err
	}

	go proxy(p.controlChannel.backendConn, p.controlChannel.qemuConn)
	go proxy(p.controlChannel.qemuConn, p.controlChannel.backendConn)
	go proxy(p.dataChannel.backendConn, p.dataChannel.qemuConn)
	go proxy(p.dataChannel.qemuConn, p.dataChannel.backendConn)

	err := <-errCh

	p.controlChannel.backendConn.Close()
	p.controlChannel.qemuConn.Close()
	p.dataChannel.backendConn.Close()
	p.dataChannel.qemuConn.Close()

	return err
}
