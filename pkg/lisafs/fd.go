// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lisafs

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/sync"
)

// FDID (file descriptor identifier) is used to identify FDs on a connection.
// Each connection has its own FDID namespace.
//
// +marshal boundCheck slice:FDIDSlice
type FDID uint32

// InvalidFDID represents an invalid FDID.
const InvalidFDID FDID = 0

// Ok returns true if f is a valid FDID.
func (f FDID) Ok() bool {
	return f != InvalidFDID
}

// genericFD can represent a ControlFD or OpenFD.
type genericFD interface {
	refsvfs2.RefCounter
}

// A ControlFD is the gateway to the backing filesystem tree node. It is an
// unusual concept. This exists to provide a safe way to do path-based
// operations on the file. It performs operations that can modify the
// filesystem tree and synchronizes these operations. See ControlFDImpl for
// supported operations.
//
// It is not an inode, because multiple control FDs are allowed to exist on the
// same file. It is not a file descriptor because it is not tied to any access
// mode, i.e. a control FD can change its access mode based on the operation
// being performed.
//
// Reference Model:
// * Each control FD holds a ref on its Node for its entire lifetime.
type ControlFD struct {
	controlFDRefs
	controlFDEntry

	// node is the filesystem node this FD is immutably associated with.
	node *Node

	// openFDs is a linked list of all FDs opened on this FD. As per reference
	// model, all open FDs hold a ref on this FD.
	openFDsMu sync.RWMutex
	openFDs   openFDList

	// All the following fields are immutable.

	// id is the unique FD identifier which identifies this FD on its connection.
	id FDID

	// conn is the backing connection owning this FD.
	conn *Connection

	// ftype is the file type of the backing inode. ftype.FileType() == ftype.
	ftype linux.FileMode

	// impl is the control FD implementation which embeds this struct. It
	// contains all the implementation specific details.
	impl ControlFDImpl
}

var _ genericFD = (*ControlFD)(nil)

// DecRef implements refsvfs2.RefCounter.DecRef. Note that the context
// parameter should never be used. It exists solely to comply with the
// refsvfs2.RefCounter interface.
func (fd *ControlFD) DecRef(context.Context) {
	fd.controlFDRefs.DecRef(func() {
		fd.conn.server.renameMu.RLock()
		fd.destroyLocked()
		fd.conn.server.renameMu.RUnlock()
	})
}

// decRefLocked is the same as DecRef except the added precondition.
//
// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) decRefLocked() {
	fd.controlFDRefs.DecRef(func() {
		fd.destroyLocked()
	})
}

// Precondition: server's rename mutex must be at least read locked.
func (fd *ControlFD) destroyLocked() {
	// Update node's control FD list.
	fd.node.removeFD(fd)

	// Drop ref on node.
	fd.node.DecRef(nil)

	// Let the FD implementation clean up.
	fd.impl.Close(fd.conn)
}

// Init must be called before first use of fd. It inserts fd into the
// filesystem tree.
//
// Preconditions:
// * server's rename mutex must be at least read locked.
// * The caller must take a ref on node which is transferred to fd.
func (fd *ControlFD) Init(c *Connection, node *Node, mode linux.FileMode, impl ControlFDImpl) {
	fd.conn = c
	fd.node = node
	fd.impl = impl
	fd.ftype = mode.FileType()
	// Initialize fd with 1 ref which is transferred to c via c.insertFD().
	fd.controlFDRefs.InitRefs()
	// Make fd reachable/discoverable.
	fd.id = c.insertFD(fd)
	node.insertFD(fd)
}

// FileType returns the file mode only containing the file type bits.
func (fd *ControlFD) FileType() linux.FileMode {
	return fd.ftype
}

// IsDir indicates whether fd represents a directory.
func (fd *ControlFD) IsDir() bool {
	return fd.ftype == unix.S_IFDIR
}

// IsRegular indicates whether fd represents a regular file.
func (fd *ControlFD) IsRegular() bool {
	return fd.ftype == unix.S_IFREG
}

// IsSymlink indicates whether fd represents a symbolic link.
func (fd *ControlFD) IsSymlink() bool {
	return fd.ftype == unix.S_IFLNK
}

// IsSocket indicates whether fd represents a socket.
func (fd *ControlFD) IsSocket() bool {
	return fd.ftype == unix.S_IFSOCK
}

// Node returns the node this FD was opened on.
func (fd *ControlFD) Node() *Node {
	return fd.node
}

// safelyRead executes the given operation with the local path node locked.
// This guarantees that fd's path will not change. fn may not any change paths.
func (fd *ControlFD) safelyRead(fn func() error) error {
	fd.conn.server.renameMu.RLock()
	defer fd.conn.server.renameMu.RUnlock()
	fd.node.opMu.RLock()
	defer fd.node.opMu.RUnlock()
	return fn()
}

// safelyWrite executes the given operation with the local path node locked in
// a writable fashion. This guarantees that no other operation is executing on
// this path node. fn may change paths inside fd.node.
func (fd *ControlFD) safelyWrite(fn func() error) error {
	fd.conn.server.renameMu.RLock()
	defer fd.conn.server.renameMu.RUnlock()
	fd.node.opMu.Lock()
	defer fd.node.opMu.Unlock()
	return fn()
}

// safelyGlobal executes the given operation with the global path lock held.
// This guarantees that no other operations is executing concurrently on this
// server. fn may change any path.
func (fd *ControlFD) safelyGlobal(fn func() error) (err error) {
	fd.conn.server.renameMu.Lock()
	defer fd.conn.server.renameMu.Unlock()
	return fn()
}

// forEachOpenFD executes fn on each FD opened on fd.
func (fd *ControlFD) forEachOpenFD(fn func(ofd *OpenFD)) {
	fd.openFDsMu.RLock()
	defer fd.openFDsMu.RUnlock()
	for ofd := fd.openFDs.Front(); ofd != nil; ofd = ofd.Next() {
		fn(ofd)
	}
}

// OpenFD represents an open file descriptor on the protocol. It resonates
// closely with a Linux file descriptor. Its operations are limited to the
// file. Its operations are not allowed to modify or traverse the filesystem
// tree. See OpenFDImpl for the supported operations.
//
// Reference Model:
// * An OpenFD takes a reference on the control FD it was opened on.
type OpenFD struct {
	openFDRefs
	openFDEntry

	// All the following fields are immutable.

	// controlFD is the ControlFD on which this FD was opened. OpenFD holds a ref
	// on controlFD for its entire lifetime.
	controlFD *ControlFD

	// id is the unique FD identifier which identifies this FD on its connection.
	id FDID

	// Access mode for this FD.
	readable bool
	writable bool

	// impl is the open FD implementation which embeds this struct. It
	// contains all the implementation specific details.
	impl OpenFDImpl
}

var _ genericFD = (*OpenFD)(nil)

// ControlFD returns the control FD on which this FD was opened.
func (fd *OpenFD) ControlFD() ControlFDImpl {
	return fd.controlFD.impl
}

// DecRef implements refsvfs2.RefCounter.DecRef. Note that the context
// parameter should never be used. It exists solely to comply with the
// refsvfs2.RefCounter interface.
func (fd *OpenFD) DecRef(context.Context) {
	fd.openFDRefs.DecRef(func() {
		fd.controlFD.openFDsMu.Lock()
		fd.controlFD.openFDs.Remove(fd)
		fd.controlFD.openFDsMu.Unlock()
		fd.controlFD.DecRef(nil) // Drop the ref on the control FD.
		fd.impl.Close(fd.controlFD.conn)
	})
}

// Init must be called before first use of fd.
func (fd *OpenFD) Init(cfd *ControlFD, flags uint32, impl OpenFDImpl) {
	// Initialize fd with 1 ref which is transferred to c via c.insertFD().
	fd.openFDRefs.InitRefs()
	fd.controlFD = cfd
	fd.id = cfd.conn.insertFD(fd)
	accessMode := flags & unix.O_ACCMODE
	fd.readable = accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR
	fd.writable = accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR
	fd.impl = impl
	cfd.IncRef() // Holds a ref on cfd for its lifetime.
	cfd.openFDsMu.Lock()
	cfd.openFDs.PushBack(fd)
	cfd.openFDsMu.Unlock()
}

// There are four different types of guarantees provided:
//
// none: There is no concurrency guarantee. The method may be invoked
// concurrently with any other method on any other FD.
//
// read: The method is guaranteed to be exclusive of any write or global
// operation that is mutating the state of the directory tree starting at this
// node. For example, this means creating new files, symlinks, directories or
// renaming a directory entry (or renaming in to this target), but the method
// may be called concurrently with other read methods.
//
// write: The method is guaranteed to be exclusive of any read, write or global
// operation that is mutating the state of the directory tree starting at this
// node, as described in read above. There may however, be other write
// operations executing concurrently on other components in the directory tree.
//
// global: The method is guaranteed to be exclusive of any read, write or
// global operation.

// ControlFDImpl contains implementation details for a ControlFD.
// Implementations of ControlFDImpl should contain their associated ControlFD
// by value as their first field.
//
// The operations that perform path traversal or any modification to the
// filesystem tree must synchronize those modifications with the server's
// rename mutex.
type ControlFDImpl interface {
	// FD returns a pointer to the embedded ControlFD.
	FD() *ControlFD

	// Close should clean up resources used by the control FD implementation.
	// Close is called after all references on the FD have been dropped and its
	// FDID has been released.
	//
	// On the server, Close has no concurrency guarantee.
	Close(c *Connection)

	// Stat returns the stat(2) results for this FD.
	//
	// On the server, Stat has a read concurrency guarantee.
	Stat(c *Connection) (linux.Statx, error)

	// SetStat sets file attributes on the backing file. This does not correspond
	// to any one Linux syscall. On Linux, this operation is performed using
	// multiple syscalls like fchmod(2), fchown(2), ftruncate(2), futimesat(2)
	// and so on. The implementation must only set attributes for fields
	// indicated by stat.Mask. Failure to set an attribute may or may not
	// terminate the entire operation. SetStat must return a uint32 which is
	// interpreted as a stat mask to indicate which attribute setting attempts
	// failed. If multiple attribute setting attempts failed, the returned error
	// may be from any one of them.
	//
	// On the server, SetStat has a write concurrency guarantee.
	SetStat(c *Connection, stat SetStatReq) (uint32, error)

	// Walk walks one path component from the directory represented by this FD.
	// Walk must open a ControlFD on the walked file.
	//
	// On the server, Walk has a read concurrency guarantee.
	Walk(c *Connection, name string) (*ControlFD, linux.Statx, error)

	// WalkStat is capable of walking multiple path components and returning the
	// stat results for each path component walked via recordStat. Stat results
	// must be returned in the order of walk.
	//
	// In case a symlink is encountered, the walk must terminate successfully on
	// the symlink including its stat result.
	//
	// The first path component of path may be "" which indicates that the first
	// stat result returned must be of this starting directory.
	//
	// On the server, WalkStat has a read concurrency guarantee.
	WalkStat(c *Connection, path StringArray, recordStat func(linux.Statx)) error

	// Open opens the control FD with the flags passed. The flags should be
	// interpreted as open(2) flags.
	//
	// Open may also optionally return a host FD for the opened file whose
	// lifecycle is independent of the OpenFD. Returns -1 if not available.
	//
	// N.B. The server must resolve any lazy paths when open is called.
	// After this point, read and write may be called on files with no
	// deletion check, so resolving in the data path is not viable.
	//
	// On the server, Open has a read concurrency guarantee.
	Open(c *Connection, flags uint32) (*OpenFD, int, error)

	// OpenCreate creates a regular file inside the directory represented by this
	// FD and then also opens the file. The created file has perms as specified
	// by mode and owners as specified by uid and gid. The file is opened with
	// the specified flags.
	//
	// OpenCreate may also optionally return a host FD for the opened file whose
	// lifecycle is independent of the OpenFD. Returns -1 if not available.
	//
	// N.B. The server must resolve any lazy paths when open is called.
	// After this point, read and write may be called on files with no
	// deletion check, so resolving in the data path is not viable.
	//
	// On the server, OpenCreate has a write concurrency guarantee.
	OpenCreate(c *Connection, mode linux.FileMode, uid UID, gid GID, name string, flags uint32) (*ControlFD, linux.Statx, *OpenFD, int, error)

	// Mkdir creates a directory inside the directory represented by this FD. The
	// created directory has perms as specified by mode and owners as specified
	// by uid and gid.
	//
	// On the server, Mkdir has a write concurrency guarantee.
	Mkdir(c *Connection, mode linux.FileMode, uid UID, gid GID, name string) (*ControlFD, linux.Statx, error)

	// Mknod creates a file inside the directory represented by this FD. The file
	// type and perms are specified by mode and owners are specified by uid and
	// gid. If the newly created file is a character or block device, minor and
	// major specify its device number.
	//
	// On the server, Mkdir has a write concurrency guarantee.
	Mknod(c *Connection, mode linux.FileMode, uid UID, gid GID, name string, minor uint32, major uint32) (*ControlFD, linux.Statx, error)

	// Symlink creates a symlink inside the directory represented by this FD. The
	// symlink has owners as specified by uid and gid and points to target.
	//
	// On the server, Symlink has a write concurrency guarantee.
	Symlink(c *Connection, name string, target string, uid UID, gid GID) (*ControlFD, linux.Statx, error)

	// Link creates a hard link to the file represented by this FD. The hard link
	// is created inside dir with the specified name.
	//
	// On the server, Link has a write concurrency guarantee for dir and read
	// concurrency guarantee for this file.
	Link(c *Connection, dir ControlFDImpl, name string) (*ControlFD, linux.Statx, error)

	// StatFS returns information about the file system associated with
	// this file.
	//
	// On the server, StatFS has no concurrency guarantee.
	StatFS(c *Connection) (StatFS, error)

	// Readlink reads the symlink's target and writes the string into the buffer
	// returned by getLinkBuf which can be used to request buffer for some size.
	//
	// On the server, Readlink has a read concurrency guarantee.
	Readlink(c *Connection, getLinkBuf func(uint32) []byte) (uint32, error)

	// Connect establishes a new host-socket backed connection with a unix domain
	// socket. On success it returns a non-blocking host socket FD whose
	// lifecycle is independent of this ControlFD.
	//
	// sockType indicates the requested type of socket and can be passed as type
	// argument to socket(2).
	//
	// On the server, Connect has a read concurrency guarantee.
	Connect(c *Connection, sockType uint32) (int, error)

	// UnlinkAt the file identified by name in this directory.
	//
	// Flags are Linux unlinkat(2) flags.
	//
	// On the server, UnlinkAt has a write concurrency guarantee.
	Unlink(c *Connection, name string, flags uint32) error

	// RenameAt renames a given file to a new name in a potentially new directory.
	//
	// oldName must be a name relative to this file, which must be a directory.
	// newName is a name relative to newDir.
	//
	// On the server, RenameAt has a global concurrency guarantee.
	RenameAt(c *Connection, oldName string, newDir ControlFDImpl, newName string) error

	// Renamed is called to notify the FD implementation that the file has been
	// renamed. FD implementation may update its state accordingly.
	//
	// On the server, Renamed has a global concurrency guarantee.
	Renamed(c *Connection)

	// GetXattr returns extended attributes of this file.
	//
	// If the value is larger than len(dataBuf), implementations may return
	// ERANGE to indicate that the buffer is too small.
	//
	// On the server, GetXattr has a read concurrency guarantee.
	GetXattr(c *Connection, name string, dataBuf []byte) (uint32, error)

	// SetXattr sets extended attributes on this file.
	//
	// On the server, SetXattr has a write concurrency guarantee.
	SetXattr(c *Connection, name string, value string, flags uint32) error

	// ListXattr lists the names of the extended attributes on this file.
	//
	// Size indicates the size of the buffer that has been allocated to hold the
	// attribute list. If the list would be larger than size, implementations may
	// return ERANGE to indicate that the buffer is too small, but they are also
	// free to ignore the hint entirely (i.e. the value returned may be larger
	// than size). All size checking is done independently at the syscall layer.
	//
	// On the server, ListXattr has a read concurrency guarantee.
	ListXattr(c *Connection, size uint64) (StringArray, error)

	// RemoveXattr removes extended attributes on this file.
	//
	// On the server, RemoveXattr has a write concurrency guarantee.
	RemoveXattr(c *Connection, name string) error
}

// OpenFDImpl contains implementation details for a OpenFD. Implementations of
// OpenFDImpl should contain their associated OpenFD by value as their first
// field.
//
// Since these operations do not perform any path traversal or any modification
// to the filesystem tree, there is no need to synchronize with rename
// operations.
type OpenFDImpl interface {
	// FD returns a pointer to the embedded OpenFD.
	FD() *OpenFD

	// Close should clean up resources used by the open FD implementation.
	// Close is called after all references on the FD have been dropped and its
	// FDID has been released.
	//
	// On the server, Close has no concurrency guarantee.
	Close(c *Connection)

	// Stat returns the stat(2) results for this FD.
	//
	// On the server, Stat has a read concurrency guarantee.
	Stat(c *Connection) (linux.Statx, error)

	// Sync is simialr to fsync(2).
	//
	// On the server, Sync has a read concurrency guarantee.
	Sync(c *Connection) error

	// Write writes buf at offset off to the backing file via this open FD. Write
	// attempts to write len(buf) bytes and returns the number of bytes written.
	//
	// On the server, Write has a write concurrency guarantee. See Open for
	// additional requirements regarding lazy path resolution.
	Write(c *Connection, buf []byte, off uint64) (uint64, error)

	// Read reads at offset off into buf from the backing file via this open FD.
	// Read attempts to read len(buf) bytes and returns the number of bytes read.
	//
	// On the server, Read has a read concurrency guarantee. See Open for
	// additional requirements regarding lazy path resolution.
	Read(c *Connection, buf []byte, off uint64) (uint64, error)

	// Allocate allows the caller to directly manipulate the allocated disk space
	// for the file. See fallocate(2) for more details.
	//
	// On the server, Allocate has a write concurrency guarantee.
	Allocate(c *Connection, mode, off, length uint64) error

	// Flush can be used to clean up the file state. Behavior is
	// implementation-specific.
	//
	// On the server, Flush has a read concurrency guarantee.
	Flush(c *Connection) error

	// Getdent64 fetches directory entries for this directory and calls
	// recordDirent for each dirent read. If seek0 is true, then the directory FD
	// is seeked to 0 and iteration starts from the beginning.
	//
	// On the server, Getdent64 has a read concurrency guarantee.
	Getdent64(c *Connection, count uint32, seek0 bool, recordDirent func(Dirent64)) error

	// Renamed is called to notify the FD implementation that the file has been
	// renamed. FD implementation may update its state accordingly.
	//
	// On the server, Renamed has a global concurrency guarantee.
	Renamed(c *Connection)
}
