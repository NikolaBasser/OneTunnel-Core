package platform

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func PipeSecurity(owner string) (string, error) {
	sid, err := windows.StringToSid(owner)
	if err != nil || sid.String() != owner {
		return "", errors.New("invalid owner")
	}
	// Read/write/synchronize, without FILE_CREATE_PIPE_INSTANCE for the owner.
	return "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;0x12019b;;;" + sid.String() + ")", nil
}
func Serve(ctx context.Context, owner string, manager *control.Manager) error {
	descriptor, err := PipeSecurity(owner)
	if err != nil {
		return err
	}
	listener, err := winio.ListenPipe(control.PipeName, &winio.PipeConfig{SecurityDescriptor: descriptor, InputBufferSize: 8192, OutputBufferSize: 8192})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	var clients sync.WaitGroup
	slots := make(chan struct{}, 16)
	defer clients.Wait()
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := listener.Accept()
		if err != nil {
			<-slots
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer func() { <-slots }()
			defer conn.Close()
			serveClient(ctx, conn, owner, manager)
		}()
	}
}
func authenticated(conn net.Conn, owner string) bool {
	file, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	var pid uint32
	if windows.GetNamedPipeClientProcessId(windows.Handle(file.Fd()), &pid) != nil {
		return false
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	return err == nil && (user.User.Sid.String() == owner || user.User.Sid.IsWellKnown(windows.WinLocalSystemSid))
}
func serveClient(ctx context.Context, conn net.Conn, owner string, manager *control.Manager) {
	if !authenticated(conn, owner) {
		return
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	request, err := control.ReadFrame[control.Request](conn)
	if err != nil {
		return
	}
	if request.Command == "watch" && control.Validate(request) == "" {
		_ = manager.Watch(ctx, func(response control.Response) error {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			return control.WriteFrame(conn, response)
		})
		return
	}
	response := manager.Dispatch(ctx, request)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = control.WriteFrame(conn, response)
}
