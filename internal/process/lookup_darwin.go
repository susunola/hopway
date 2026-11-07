//go:build !hopway_native && darwin && cgo

package process

/*
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <libproc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <unistd.h>

struct hopway_tuple {
	uint8_t client[16];
	uint8_t server[16];
	uint16_t client_port;
	uint16_t server_port;
	int address_size;
	int protocol;
};

struct hopway_peer {
	int pid;
	int fd;
	uint64_t generation;
	int priority;
	int ambiguous;
};

static const struct in_sockinfo *hopway_inet_info(const struct socket_info *socket, int protocol) {
	if (socket->soi_protocol != protocol || (socket->soi_state & SOI_S_NOFDREF) != 0) {
		return NULL;
	}
	if (protocol == IPPROTO_TCP && socket->soi_kind == SOCKINFO_TCP) {
		return &socket->soi_proto.pri_tcp.tcpsi_ini;
	}
	if (protocol == IPPROTO_UDP && socket->soi_kind == SOCKINFO_IN) {
		return &socket->soi_proto.pri_in;
	}
	return NULL;
}

static int hopway_fd_matches(int pid, int fd, int protocol, uint64_t generation) {
	struct socket_fdinfo info;
	if (proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info)) != sizeof(info)) {
		return 0;
	}
	const struct in_sockinfo *socket = hopway_inet_info(&info.psi, protocol);
	return socket != NULL && socket->insi_gencnt == generation;
}

static struct proc_fdinfo *hopway_list_fds(int pid, int *count) {
	*count = 0;
	const int max_bytes = 32768 * sizeof(struct proc_fdinfo);
	int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
	if (size <= 0 || size > max_bytes) {
		return NULL;
	}
	struct proc_fdinfo *fds = malloc(size);
	if (fds == NULL) {
		return NULL;
	}
	int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, size);
	*count = bytes > 0 && bytes <= size ? bytes / sizeof(*fds) : 0;
	return fds;
}

static int hopway_find_socket(int pid, int protocol, uint64_t generation) {
	int count;
	struct proc_fdinfo *fds = hopway_list_fds(pid, &count);
	int result = -1;
	for (int i = 0; i < count; i++) {
		if (fds[i].proc_fdtype == PROX_FDTYPE_SOCKET &&
		    hopway_fd_matches(pid, fds[i].proc_fd, protocol, generation)) {
			result = fds[i].proc_fd;
			break;
		}
	}
	free(fds);
	return result;
}

static int hopway_tuple_priority(const struct hopway_tuple *tuple, const struct in_sockinfo *socket) {
	if (ntohs((uint16_t)socket->insi_lport) != tuple->client_port) {
		return 0;
	}
	const void *source;
	const void *target;
	if (tuple->address_size == 4 && (socket->insi_vflag & INI_IPV4)) {
		source = &socket->insi_laddr.ina_46.i46a_addr4;
		target = &socket->insi_faddr.ina_46.i46a_addr4;
	} else if (tuple->address_size == 16 && (socket->insi_vflag & INI_IPV6)) {
		source = &socket->insi_laddr.ina_6;
		target = &socket->insi_faddr.ina_6;
	} else {
		return 0;
	}
	int same_source = memcmp(source, tuple->client, tuple->address_size) == 0;
	if (same_source && ntohs((uint16_t)socket->insi_fport) == tuple->server_port &&
	    memcmp(target, tuple->server, tuple->address_size) == 0) {
		return 3;
	}
	const uint8_t unspecified[16] = {0};
	if (tuple->protocol != IPPROTO_UDP || socket->insi_fport != 0 ||
	    memcmp(target, unspecified, tuple->address_size) != 0) {
		return 0;
	}
	if (same_source) {
		return 2;
	}
	return memcmp(source, unspecified, tuple->address_size) == 0;
}

static void hopway_scan_process(int pid, const struct hopway_tuple *tuple, struct hopway_peer *best) {
	int count;
	struct proc_fdinfo *fds = hopway_list_fds(pid, &count);
	for (int i = 0; i < count; i++) {
		int fd = fds[i].proc_fd;
		struct socket_fdinfo info;
		if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET ||
		    proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info)) != sizeof(info)) {
			continue;
		}
		const struct in_sockinfo *socket = hopway_inet_info(&info.psi, tuple->protocol);
		if (socket == NULL || socket->insi_gencnt == 0) {
			continue;
		}
		int priority = hopway_tuple_priority(tuple, socket);
		if (priority > best->priority) {
			*best = (struct hopway_peer){pid, fd, socket->insi_gencnt, priority, 0};
		} else if (priority > 0 && priority == best->priority &&
		    (pid != best->pid || socket->insi_gencnt != best->generation)) {
			best->ambiguous = 1;
		}
	}
	free(fds);
}

static struct hopway_peer hopway_find_peer(const struct hopway_tuple *tuple, int hint) {
	struct hopway_peer best = {0};
	if (tuple->protocol == IPPROTO_TCP && hint > 0) {
		hopway_scan_process(hint, tuple, &best);
		if (best.priority == 3 && !best.ambiguous) {
			return best;
		}
	}
	int pids[4096];
	int bytes = proc_listpids(PROC_UID_ONLY, geteuid(), pids, sizeof(pids));
	if (bytes <= 0 || bytes >= sizeof(pids)) {
		return (struct hopway_peer){0};
	}
	int count = bytes / sizeof(*pids);
	for (int i = 0; i < count; i++) {
		if (pids[i] > 0 && pids[i] != hint) {
			hopway_scan_process(pids[i], tuple, &best);
			if (tuple->protocol == IPPROTO_TCP && best.priority == 3 && !best.ambiguous) {
				break;
			}
		}
	}
	return best;
}

static void hopway_bundle_id(const unsigned char *input, int size, char *output, int capacity) {
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, input, size);
	if (data == NULL) {
		return;
	}
	CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, NULL);
	CFRelease(data);
	if (plist == NULL) {
		return;
	}
	if (CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
		CFTypeRef value = CFDictionaryGetValue((CFDictionaryRef)plist, kCFBundleIdentifierKey);
		if (value != NULL && CFGetTypeID(value) == CFStringGetTypeID() &&
		    !CFStringGetCString((CFStringRef)value, output, capacity, kCFStringEncodingUTF8)) {
			output[0] = '\0';
		}
	}
	CFRelease(plist);
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ownerCacheTTL  = 500 * time.Millisecond
	ownerCacheSize = 1024
)

var errUnknownSocket = errors.New("local socket owner could not be verified")
var errAmbiguousSocket = errors.Join(errUnknownSocket, errors.New("multiple live sockets match the source"))

type socketKey struct {
	protocol int
	client   netip.AddrPort
	server   netip.AddrPort
}

type socketIdentity struct {
	pid        uint32
	generation uint64
	fdHint     int // descriptor + 1, zero when discovered from the socket table
}

type processStamp struct {
	startSec  uint64
	startUsec uint64
	path      string
	uid       uint32
}

type cachedOwner struct {
	socket  socketIdentity
	fd      int
	process processStamp
	owner   *Owner
	until   time.Time
}

// A tuple alone is not an identity. Each cache hit verifies the current
// process instance, executable and kernel generation of its descriptor.
type socketOwnerLookup struct {
	mu       sync.Mutex
	cache    map[socketKey]cachedOwner
	discover func(socketKey) (socketIdentity, error)
	findFD   func(socketIdentity, int) int
	matchFD  func(socketIdentity, int, int) bool
	stamp    func(uint32) (processStamp, error)
	bundleID func(string) string
	now      func() time.Time
}

var lastTCPProcess atomic.Uint32

var darwinOwners = socketOwnerLookup{
	cache:    make(map[socketKey]cachedOwner),
	discover: discoverDarwinSocket,
	findFD: func(socket socketIdentity, protocol int) int {
		if socket.fdHint != 0 {
			return socket.fdHint - 1
		}
		return int(C.hopway_find_socket(C.int(socket.pid), C.int(protocol), C.uint64_t(socket.generation)))
	},
	matchFD: func(socket socketIdentity, fd, protocol int) bool {
		return C.hopway_fd_matches(C.int(socket.pid), C.int(fd), C.int(protocol), C.uint64_t(socket.generation)) != 0
	},
	stamp:    readProcessStamp,
	bundleID: readBundleID,
	now:      time.Now,
}

func Lookup(client, server netip.AddrPort) (*Owner, error) {
	return darwinOwners.lookup(socketKey{unix.IPPROTO_TCP, normalizedAddrPort(client), normalizedAddrPort(server)})
}

func LookupUDP(client, server netip.AddrPort) (*Owner, error) {
	return darwinOwners.lookup(socketKey{unix.IPPROTO_UDP, normalizedAddrPort(client), normalizedAddrPort(server)})
}

func normalizedAddrPort(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port())
}

func (lookup *socketOwnerLookup) lookup(key socketKey) (*Owner, error) {
	if !key.client.IsValid() || !key.server.IsValid() {
		return nil, errUnknownSocket
	}
	lookup.mu.Lock()
	cached, exists := lookup.cache[key]
	lookup.mu.Unlock()
	reusable := exists && lookup.now().Before(cached.until)
	if reusable && key.protocol == unix.IPPROTO_TCP && lookup.verify(key, cached) {
		return cached.owner, nil
	}

	// UDP sockets can share a port. Always consult the current socket table
	// before reusing their metadata so a newly ambiguous port fails closed.
	socket, err := lookup.discover(key)
	if err != nil {
		return nil, err
	}
	if reusable && key.protocol == unix.IPPROTO_UDP && socket == cached.socket && lookup.verify(key, cached) {
		return cached.owner, nil
	}
	before, err := lookup.stamp(socket.pid)
	if err != nil {
		return nil, err
	}
	fd := lookup.findFD(socket, key.protocol)
	if fd < 0 {
		return nil, errUnknownSocket
	}
	name := ""
	if account, err := user.LookupId(strconv.FormatUint(uint64(before.uid), 10)); err == nil {
		name = account.Username
	}
	owner := newOwner(socket.pid, before.path, name)
	owner.BundleID = lookup.bundleID(before.path)
	entry := cachedOwner{socket: socket, fd: fd, process: before, owner: owner, until: lookup.now().Add(ownerCacheTTL)}
	if !lookup.verify(key, entry) {
		return nil, errUnknownSocket
	}
	lookup.store(key, entry)
	return owner, nil
}

func (lookup *socketOwnerLookup) verify(key socketKey, entry cachedOwner) bool {
	if !lookup.matchFD(entry.socket, entry.fd, key.protocol) {
		return false
	}
	current, err := lookup.stamp(entry.socket.pid)
	return err == nil && current == entry.process
}

func (lookup *socketOwnerLookup) store(key socketKey, entry cachedOwner) {
	lookup.mu.Lock()
	defer lookup.mu.Unlock()
	if _, exists := lookup.cache[key]; !exists && len(lookup.cache) >= ownerCacheSize {
		now := lookup.now()
		for key, value := range lookup.cache {
			if !now.Before(value.until) {
				delete(lookup.cache, key)
			}
		}
		if len(lookup.cache) >= ownerCacheSize {
			for key := range lookup.cache {
				delete(lookup.cache, key)
				break
			}
		}
	}
	lookup.cache[key] = entry
}

func readProcessStamp(pid uint32) (processStamp, error) {
	var info C.struct_proc_bsdinfo
	size := C.int(unsafe.Sizeof(info))
	if C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0, unsafe.Pointer(&info), size) != size ||
		uint32(info.pbi_pid) != pid || info.pbi_flags&C.PROC_FLAG_INEXIT != 0 {
		return processStamp{}, errUnknownSocket
	}
	var path [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	if C.proc_pidpath(C.int(pid), unsafe.Pointer(&path[0]), C.uint32_t(len(path))) <= 0 {
		return processStamp{}, errUnknownSocket
	}
	return processStamp{uint64(info.pbi_start_tvsec), uint64(info.pbi_start_tvusec), C.GoString(&path[0]), uint32(info.pbi_uid)}, nil
}

func readBundleID(path string) string {
	bundle := bundleRoot(path)
	if bundle == "" {
		return ""
	}
	file, err := os.OpenFile(filepath.Join(bundle, "Contents", "Info.plist"), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer file.Close()
	const maxPlist = 256 << 10
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPlist {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPlist+1))
	if err != nil || len(data) == 0 || len(data) > maxPlist {
		return ""
	}
	var value [256]C.char
	C.hopway_bundle_id((*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)), &value[0], C.int(len(value)))
	return C.GoString(&value[0])
}

func discoverDarwinSocket(key socketKey) (socketIdentity, error) {
	name := "net.inet.tcp.pcblist_n"
	if key.protocol == unix.IPPROTO_UDP {
		name = "net.inet.udp.pcblist_n"
	}
	if data, err := unix.SysctlRaw(name); err == nil {
		socket, err := findDarwinSocket(data, key)
		if err == nil || err == errAmbiguousSocket {
			return socket, err
		}
	}
	// Some macOS builds restrict the PCB table to the calling process.
	// Search descriptors of the same user without requesting privileges.
	client, server := key.client.Addr().AsSlice(), key.server.Addr().AsSlice()
	if len(client) != len(server) || len(client) == 0 {
		return socketIdentity{}, errUnknownSocket
	}
	tuple := C.struct_hopway_tuple{
		client_port: C.uint16_t(key.client.Port()), server_port: C.uint16_t(key.server.Port()),
		address_size: C.int(len(client)), protocol: C.int(key.protocol),
	}
	for i := range client {
		tuple.client[i], tuple.server[i] = C.uint8_t(client[i]), C.uint8_t(server[i])
	}
	hint := C.int(0)
	if key.protocol == unix.IPPROTO_TCP {
		hint = C.int(lastTCPProcess.Load())
	}
	peer := C.hopway_find_peer(&tuple, hint)
	if peer.ambiguous != 0 {
		return socketIdentity{}, errAmbiguousSocket
	}
	if peer.pid <= 0 || peer.generation == 0 {
		return socketIdentity{}, errUnknownSocket
	}
	if key.protocol == unix.IPPROTO_TCP {
		lastTCPProcess.Store(uint32(peer.pid))
	}
	return socketIdentity{pid: uint32(peer.pid), generation: uint64(peer.generation), fdHint: int(peer.fd) + 1}, nil
}

func findDarwinSocket(data []byte, key socketKey) (socketIdentity, error) {
	// The kernel emits a 24-byte generation header followed by 8-byte
	// aligned length/kind records. Walk lengths instead of assuming that
	// a complete TCP or UDP row is a fixed size on every macOS version.
	const (
		generationHeader = 24
		socketRecord     = 1
		inpcbRecord      = 16
		pcbGeneration    = 28 // xinpcb_n is packed on a 4-byte boundary
		socketLastPID    = 68
	)
	native := binary.NativeEndian
	if len(data) < generationHeader || native.Uint32(data[:4]) != generationHeader {
		return socketIdentity{}, errUnknownSocket
	}
	var selected socketIdentity
	best, priority := 0, 0
	var ambiguous bool
	var generation uint64
	for data = data[generationHeader:]; len(data) > generationHeader; {
		length := int(native.Uint32(data[:4]))
		kind := native.Uint32(data[4:8])
		aligned := (length + 7) &^ 7
		if length < 8 || aligned > len(data) {
			return socketIdentity{}, errUnknownSocket
		}
		record := data[:length]
		data = data[aligned:]
		switch kind {
		case inpcbRecord:
			priority = darwinSocketPriority(record, key)
			if priority != 0 {
				generation = native.Uint64(record[pcbGeneration : pcbGeneration+8])
			}
		case socketRecord:
			if priority == 0 || priority < best || len(record) < socketLastPID+4 {
				continue
			}
			pid := native.Uint32(record[socketLastPID : socketLastPID+4])
			candidate := socketIdentity{pid: pid, generation: generation}
			if priority > best {
				selected, best, ambiguous = candidate, priority, false
			} else if candidate != selected {
				ambiguous = true
			}
			priority = 0
		}
	}
	if ambiguous {
		return socketIdentity{}, errAmbiguousSocket
	}
	if best == 0 || selected.pid == 0 || selected.generation == 0 {
		return socketIdentity{}, errUnknownSocket
	}
	return selected, nil
}

func darwinSocketPriority(inpcb []byte, key socketKey) int {
	if len(inpcb) < 80 || binary.BigEndian.Uint16(inpcb[18:20]) != key.client.Port() {
		return 0
	}
	var source, target netip.Addr
	flag := inpcb[44]
	switch {
	case key.client.Addr().Is4() && flag&1 != 0:
		target = netip.AddrFrom4([4]byte(inpcb[60:64]))
		source = netip.AddrFrom4([4]byte(inpcb[76:80]))
	case key.client.Addr().Is6() && flag&2 != 0:
		target = netip.AddrFrom16([16]byte(inpcb[48:64]))
		source = netip.AddrFrom16([16]byte(inpcb[64:80]))
	default:
		return 0
	}
	port := binary.BigEndian.Uint16(inpcb[16:18])
	if source == key.client.Addr() && target == key.server.Addr() && port == key.server.Port() {
		return 3
	}
	if key.protocol != unix.IPPROTO_UDP || !target.IsUnspecified() || port != 0 {
		return 0
	}
	if source == key.client.Addr() {
		return 2
	}
	if source.IsUnspecified() {
		return 1
	}
	return 0
}
