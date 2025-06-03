package drivers

import (
	"fmt"
	"io"
	"net"
	"os/exec"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

func handleConnection(
	cname string,
	conn net.Conn,
	remotePort int,
) {
	defer conn.Close()
	log.Debugf("handling connection to tcp://%s:%d", cname, remotePort)

	cmd := exec.Command(
		"docker", "exec",
		"-i",
		cname,
		"dial-stdio",
		fmt.Sprintf("tcp://localhost:%d", remotePort),
	)
	// Ignore stderr, stdin and stdout are used for communication
	// between the parent process and the child process.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Errorf("failed to open stdin pipe: %v", err)
		return
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("failed to open stdout pipe: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Errorf("failed to start command: %v", err)
		return
	}

	go func() {
		if _, err := io.Copy(stdin, conn); err != nil {
			log.Debugf("failed to copy from conn to stdin: %v", err)
		}
		cmd.Process.Kill()
	}()

	go func() {
		if _, err := io.Copy(conn, stdout); err != nil {
			log.Debugf("failed to copy from stdout to conn: %v", err)
		}
		cmd.Process.Kill()
	}()

	if err := cmd.Wait(); err != nil {
		log.Debugf("command failed: %v", err)
	}
}

// ForwardTCP forwards localPort on host to a remotePort on a container cname.
func ForwardTCP(
	stopCh <-chan struct{},
	cname string,
	localPort, remotePort int,
) error {
	lst, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		return err
	}
	defer lst.Close()

	go func() {
		<-stopCh
		lst.Close()
	}()

	for {
		conn, err := lst.Accept()
		if err != nil {
			return err
		}
		go handleConnection(cname, conn, remotePort)
	}
	panic("unreachable")
}
