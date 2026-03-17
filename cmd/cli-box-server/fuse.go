package main

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	pb "github.com/cli-auth/cli-box/proto"
)

// RemoteNode backs a FUSE filesystem with gRPC calls to the local's FileSystem service.
type RemoteNode struct {
	fs.Inode
	client pb.FileSystemClient
	path   string
}

var _ = (fs.InodeEmbedder)((*RemoteNode)(nil))
var _ = (fs.NodeLookuper)((*RemoteNode)(nil))
var _ = (fs.NodeReaddirer)((*RemoteNode)(nil))
var _ = (fs.NodeGetattrer)((*RemoteNode)(nil))
var _ = (fs.NodeOpener)((*RemoteNode)(nil))
var _ = (fs.NodeReader)((*RemoteNode)(nil))
var _ = (fs.NodeWriter)((*RemoteNode)(nil))
var _ = (fs.NodeCreater)((*RemoteNode)(nil))
var _ = (fs.NodeMkdirer)((*RemoteNode)(nil))
var _ = (fs.NodeRmdirer)((*RemoteNode)(nil))
var _ = (fs.NodeUnlinker)((*RemoteNode)(nil))
var _ = (fs.NodeRenamer)((*RemoteNode)(nil))
var _ = (fs.NodeReadlinker)((*RemoteNode)(nil))
var _ = (fs.NodeSymlinker)((*RemoteNode)(nil))
var _ = (fs.NodeLinker)((*RemoteNode)(nil))
var _ = (fs.NodeSetattrer)((*RemoteNode)(nil))
var _ = (fs.NodeStatfser)((*RemoteNode)(nil))
var _ = (fs.NodeAccesser)((*RemoteNode)(nil))

func protoToErrno(e int32) syscall.Errno {
	if e == 0 {
		return 0
	}
	return syscall.Errno(e)
}

func fillEntryOut(attr *pb.FileAttr, out *fuse.EntryOut) {
	if attr == nil {
		return
	}
	out.Ino = attr.Ino
	out.Size = attr.Size
	out.Mode = attr.Mode
	out.Nlink = attr.Nlink
	out.Owner.Uid = attr.Uid
	out.Owner.Gid = attr.Gid
	out.Atime = uint64(attr.AtimeSec)
	out.Atimensec = uint32(attr.AtimeNsec)
	out.Mtime = uint64(attr.MtimeSec)
	out.Mtimensec = uint32(attr.MtimeNsec)
	out.Ctime = uint64(attr.CtimeSec)
	out.Ctimensec = uint32(attr.CtimeNsec)
}

func fillAttrOut(attr *pb.FileAttr, out *fuse.AttrOut) {
	if attr == nil {
		return
	}
	out.Ino = attr.Ino
	out.Size = attr.Size
	out.Mode = attr.Mode
	out.Nlink = attr.Nlink
	out.Owner.Uid = attr.Uid
	out.Owner.Gid = attr.Gid
	out.Atime = uint64(attr.AtimeSec)
	out.Atimensec = uint32(attr.AtimeNsec)
	out.Mtime = uint64(attr.MtimeSec)
	out.Mtimensec = uint32(attr.MtimeNsec)
	out.Ctime = uint64(attr.CtimeSec)
	out.Ctimensec = uint32(attr.CtimeNsec)
}

func stableAttrFromProto(attr *pb.FileAttr) fs.StableAttr {
	if attr == nil {
		return fs.StableAttr{}
	}
	return fs.StableAttr{Mode: attr.Mode, Ino: attr.Ino}
}

func (n *RemoteNode) child(name string) *RemoteNode {
	p := n.path + "/" + name
	if n.path == "" {
		p = "/" + name
	}
	return &RemoteNode{client: n.client, path: p}
}

func (n *RemoteNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	resp, err := n.client.GetAttr(ctx, &pb.GetAttrRequest{Path: n.path})
	if err != nil {
		return syscall.EIO
	}
	if resp.Errno != 0 {
		return protoToErrno(resp.Errno)
	}
	fillAttrOut(resp.Attr, out)
	return 0
}

func (n *RemoteNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	resp, err := n.client.Lookup(ctx, &pb.LookupRequest{Parent: n.path, Name: name})
	if err != nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, protoToErrno(resp.Errno)
	}
	fillEntryOut(resp.Attr, out)
	ch := n.child(name)
	inode := n.NewInode(ctx, ch, stableAttrFromProto(resp.Attr))
	return inode, 0
}

func (n *RemoteNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	odr, err := n.client.OpenDir(ctx, &pb.OpenDirRequest{Path: n.path})
	if err != nil {
		return nil, syscall.EIO
	}
	if odr.Errno != 0 {
		return nil, protoToErrno(odr.Errno)
	}

	rdr, err := n.client.ReadDir(ctx, &pb.ReadDirRequest{Path: n.path, Fh: odr.Fh})
	if err != nil {
		n.client.ReleaseDir(ctx, &pb.ReleaseDirRequest{Fh: odr.Fh})
		return nil, syscall.EIO
	}
	n.client.ReleaseDir(ctx, &pb.ReleaseDirRequest{Fh: odr.Fh})

	if rdr.Errno != 0 {
		return nil, protoToErrno(rdr.Errno)
	}

	entries := make([]fuse.DirEntry, len(rdr.Entries))
	for i, e := range rdr.Entries {
		entries[i] = fuse.DirEntry{
			Name: e.Name,
			Ino:  e.Ino,
			Mode: e.Mode,
		}
	}
	return fs.NewListDirStream(entries), 0
}

func (n *RemoteNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	resp, err := n.client.ReadLink(ctx, &pb.ReadLinkRequest{Path: n.path})
	if err != nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, protoToErrno(resp.Errno)
	}
	return []byte(resp.Target), 0
}

// remoteFileHandle tracks an open file on the remote side.
type remoteFileHandle struct {
	client pb.FileSystemClient
	path   string
	fh     uint64
}

var _ = (fs.FileReader)((*remoteFileHandle)(nil))
var _ = (fs.FileWriter)((*remoteFileHandle)(nil))
var _ = (fs.FileFsyncer)((*remoteFileHandle)(nil))
var _ = (fs.FileReleaser)((*remoteFileHandle)(nil))

func (n *RemoteNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	resp, err := n.client.Open(ctx, &pb.OpenRequest{Path: n.path, Flags: flags})
	if err != nil {
		return nil, 0, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, 0, protoToErrno(resp.Errno)
	}
	return &remoteFileHandle{client: n.client, path: n.path, fh: resp.Fh}, 0, 0
}

func (n *RemoteNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	rfh, ok := fh.(*remoteFileHandle)
	if !ok {
		return nil, syscall.EBADF
	}
	resp, err := rfh.client.Read(ctx, &pb.ReadRequest{
		Path:   rfh.path,
		Fh:     rfh.fh,
		Offset: off,
		Size:   uint32(len(dest)),
	})
	if err != nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, protoToErrno(resp.Errno)
	}
	return fuse.ReadResultData(resp.Data), 0
}

func (n *RemoteNode) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	rfh, ok := fh.(*remoteFileHandle)
	if !ok {
		return 0, syscall.EBADF
	}
	resp, err := rfh.client.Write(ctx, &pb.WriteRequest{
		Path:   rfh.path,
		Fh:     rfh.fh,
		Offset: off,
		Data:   data,
	})
	if err != nil {
		return 0, syscall.EIO
	}
	if resp.Errno != 0 {
		return 0, protoToErrno(resp.Errno)
	}
	return resp.Written, 0
}

func (h *remoteFileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	resp, err := h.client.Read(ctx, &pb.ReadRequest{
		Path:   h.path,
		Fh:     h.fh,
		Offset: off,
		Size:   uint32(len(dest)),
	})
	if err != nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, protoToErrno(resp.Errno)
	}
	return fuse.ReadResultData(resp.Data), 0
}

func (h *remoteFileHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	resp, err := h.client.Write(ctx, &pb.WriteRequest{
		Path:   h.path,
		Fh:     h.fh,
		Offset: off,
		Data:   data,
	})
	if err != nil {
		return 0, syscall.EIO
	}
	if resp.Errno != 0 {
		return 0, protoToErrno(resp.Errno)
	}
	return resp.Written, 0
}

func (h *remoteFileHandle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	resp, err := h.client.Fsync(ctx, &pb.FsyncRequest{
		Path:     h.path,
		Fh:       h.fh,
		Datasync: flags&1 != 0,
	})
	if err != nil {
		return syscall.EIO
	}
	return protoToErrno(resp.Errno)
}

func (h *remoteFileHandle) Release(ctx context.Context) syscall.Errno {
	resp, err := h.client.Release(ctx, &pb.ReleaseRequest{Path: h.path, Fh: h.fh})
	if err != nil {
		return syscall.EIO
	}
	return protoToErrno(resp.Errno)
}

func (n *RemoteNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	ch := n.child(name)
	resp, err := n.client.Create(ctx, &pb.CreateRequest{
		Path:  ch.path,
		Mode:  mode,
		Flags: flags,
	})
	if err != nil {
		return nil, nil, 0, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, nil, 0, protoToErrno(resp.Errno)
	}
	fillEntryOut(resp.Attr, out)
	inode := n.NewInode(ctx, ch, stableAttrFromProto(resp.Attr))
	fh := &remoteFileHandle{client: n.client, path: ch.path, fh: resp.Fh}
	return inode, fh, 0, 0
}

func (n *RemoteNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	ch := n.child(name)
	resp, err := n.client.Mkdir(ctx, &pb.MkdirRequest{Path: ch.path, Mode: mode})
	if err != nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, protoToErrno(resp.Errno)
	}
	fillEntryOut(resp.Attr, out)
	inode := n.NewInode(ctx, ch, stableAttrFromProto(resp.Attr))
	return inode, 0
}

func (n *RemoteNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	ch := n.child(name)
	resp, err := n.client.Rmdir(ctx, &pb.RmdirRequest{Path: ch.path})
	if err != nil {
		return syscall.EIO
	}
	return protoToErrno(resp.Errno)
}

func (n *RemoteNode) Unlink(ctx context.Context, name string) syscall.Errno {
	ch := n.child(name)
	resp, err := n.client.Unlink(ctx, &pb.UnlinkRequest{Path: ch.path})
	if err != nil {
		return syscall.EIO
	}
	return protoToErrno(resp.Errno)
}

func (n *RemoteNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	np, ok := newParent.(*RemoteNode)
	if !ok {
		return syscall.EIO
	}
	oldCh := n.child(name)
	newCh := np.child(newName)
	resp, err := n.client.Rename(ctx, &pb.RenameRequest{OldPath: oldCh.path, NewPath: newCh.path})
	if err != nil {
		return syscall.EIO
	}
	return protoToErrno(resp.Errno)
}

func (n *RemoteNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	ch := n.child(name)
	resp, err := n.client.Symlink(ctx, &pb.SymlinkRequest{Target: target, LinkPath: ch.path})
	if err != nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, protoToErrno(resp.Errno)
	}
	fillEntryOut(resp.Attr, out)
	inode := n.NewInode(ctx, ch, stableAttrFromProto(resp.Attr))
	return inode, 0
}

func (n *RemoteNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	tgt, ok := target.(*RemoteNode)
	if !ok {
		return nil, syscall.EIO
	}
	ch := n.child(name)
	resp, err := n.client.Link(ctx, &pb.LinkRequest{OldPath: tgt.path, NewPath: ch.path})
	if err != nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, protoToErrno(resp.Errno)
	}
	fillEntryOut(resp.Attr, out)
	inode := n.NewInode(ctx, ch, stableAttrFromProto(resp.Attr))
	return inode, 0
}

func (n *RemoteNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if m, ok := in.GetMode(); ok {
		resp, err := n.client.Chmod(ctx, &pb.ChmodRequest{Path: n.path, Mode: m})
		if err != nil {
			return syscall.EIO
		}
		if resp.Errno != 0 {
			return protoToErrno(resp.Errno)
		}
	}

	if uid, ok := in.GetUID(); ok {
		gid, _ := in.GetGID()
		resp, err := n.client.Chown(ctx, &pb.ChownRequest{Path: n.path, Uid: uid, Gid: gid})
		if err != nil {
			return syscall.EIO
		}
		if resp.Errno != 0 {
			return protoToErrno(resp.Errno)
		}
	}

	if sz, ok := in.GetSize(); ok {
		resp, err := n.client.Truncate(ctx, &pb.TruncateRequest{Path: n.path, Size: int64(sz)})
		if err != nil {
			return syscall.EIO
		}
		if resp.Errno != 0 {
			return protoToErrno(resp.Errno)
		}
	}

	// Refresh attributes
	gaResp, err := n.client.GetAttr(ctx, &pb.GetAttrRequest{Path: n.path})
	if err != nil {
		return syscall.EIO
	}
	if gaResp.Errno != 0 {
		return protoToErrno(gaResp.Errno)
	}
	fillAttrOut(gaResp.Attr, out)
	return 0
}

func (n *RemoteNode) Access(ctx context.Context, mask uint32) syscall.Errno {
	return 0
}

func (n *RemoteNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	resp, err := n.client.StatFs(ctx, &pb.StatFsRequest{Path: n.path})
	if err != nil {
		return syscall.EIO
	}
	if resp.Errno != 0 {
		return protoToErrno(resp.Errno)
	}
	out.Blocks = resp.Blocks
	out.Bfree = resp.Bfree
	out.Bavail = resp.Bavail
	out.Files = resp.Files
	out.Ffree = resp.Ffree
	out.Bsize = resp.Bsize
	out.Frsize = resp.Frsize
	out.NameLen = resp.Namelen
	return 0
}
