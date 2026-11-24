package main

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestListenWithinReturnsTheListener(t *testing.T) {
	listener, err := listenWithin("绑定测试端口", time.Second, func() (*net.TCPListener, error) {
		return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if listener.Addr() == nil {
		t.Fatal("listener has no address")
	}
}

func TestListenWithinNamesTheStageAndClosesALateListener(t *testing.T) {
	var late atomic.Pointer[net.TCPListener]
	_, err := listenWithin("绑定卡住的端口", 20*time.Millisecond, func() (*net.TCPListener, error) {
		time.Sleep(80 * time.Millisecond)
		listener, listenErr := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		late.Store(listener)
		return listener, listenErr
	})
	var stage *startupError
	if !errors.As(err, &stage) || stage.Stage != "绑定卡住的端口" || stage.After != 20*time.Millisecond {
		t.Fatalf("want a stage timeout, got %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if listener := late.Load(); listener != nil {
			if _, acceptErr := listener.Accept(); acceptErr == nil {
				t.Fatal("listener created after the timeout was left open")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the delayed bind never returned")
}

func TestLoadWithinReleasesTheLateValue(t *testing.T) {
	released := make(chan string, 1)
	_, err := loadWithin("读取配置", 20*time.Millisecond, func() (string, error) {
		time.Sleep(80 * time.Millisecond)
		return "late supervisor", nil
	}, func(value string) {
		released <- value
	})
	var stage *startupError
	if !errors.As(err, &stage) || stage.Stage != "读取配置" {
		t.Fatalf("want a stage timeout, got %v", err)
	}
	select {
	case value := <-released:
		if value != "late supervisor" {
			t.Fatalf("released %q", value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late value was not released")
	}
}

func TestLoadWithinKeepsAStageError(t *testing.T) {
	want := &startupError{Stage: "读取配置", After: time.Second}
	_, err := loadWithin("包装层", time.Second, func() (struct{}, error) {
		return struct{}{}, want
	}, nil)
	if err != want {
		t.Fatalf("stage error was wrapped twice: %v", err)
	}
}

func TestStartupErrorMentionsStageAndCause(t *testing.T) {
	cause := errors.New("port 1080 is already in use")
	err := asStartupError("绑定 SOCKS5 端口", cause)
	if !errors.Is(err, cause) {
		t.Fatal("cause is not unwrapable")
	}
	message := err.Error()
	if !containsAll(message, "绑定 SOCKS5 端口", "port 1080") {
		t.Fatalf("message %q does not name the stage and the cause", message)
	}
}

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		found := false
		for i := 0; i+len(part) <= len(value); i++ {
			if value[i:i+len(part)] == part {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
