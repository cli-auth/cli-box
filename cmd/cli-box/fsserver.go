package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cli-auth/cli-box/pkg/fsutil"
	pb "github.com/cli-auth/cli-box/proto"
)

// FSServer implements the FileSystem gRPC service, backed by the local filesystem.
// All paths are resolved relative to root.
type FSServer struct {
	pb.UnimplementedFileSystemServer
	root  string
	files *fsutil.HandleTracker
	dirs  *fsutil.HandleTracker
}

func NewFSServer(root string) *FSServer {
	return &FSServer{
		root:  root,
		files: fsutil.NewHandleTracker(),
		dirs:  fsutil.NewHandleTracker(),
	}
}

func (s *FSServer) realPath(p string) string {
	return filepath.Join(s.root, filepath.Clean("/"+p))
}

func errnoVal(err error) int32 {
	if err == nil {
		return 0
	}
	if pe, ok := err.(*os.PathError); ok {
		err = pe.Err
	}
	if pe, ok := err.(*os.LinkError); ok {
		err = pe.Err
	}
	if errno, ok := err.(syscall.Errno); ok {
		return int32(errno)
	}
	return int32(syscall.EIO)
}

func (s *FSServer) GetAttr(_ context.Context, req *pb.GetAttrRequest) (*pb.GetAttrResponse, error) {
	attr, err := fsutil.Lstat(s.realPath(req.Path))
	if err != nil {
		return &pb.GetAttrResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.GetAttrResponse{Attr: attr}, nil
}

func (s *FSServer) Lookup(_ context.Context, req *pb.LookupRequest) (*pb.LookupResponse, error) {
	full := filepath.Join(s.realPath(req.Parent), req.Name)
	attr, err := fsutil.Lstat(full)
	if err != nil {
		return &pb.LookupResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.LookupResponse{Attr: attr}, nil
}

func (s *FSServer) ReadLink(_ context.Context, req *pb.ReadLinkRequest) (*pb.ReadLinkResponse, error) {
	target, err := os.Readlink(s.realPath(req.Path))
	if err != nil {
		return &pb.ReadLinkResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.ReadLinkResponse{Target: target}, nil
}

func (s *FSServer) OpenDir(_ context.Context, req *pb.OpenDirRequest) (*pb.OpenDirResponse, error) {
	f, err := os.Open(s.realPath(req.Path))
	if err != nil {
		return &pb.OpenDirResponse{Errno: errnoVal(err)}, nil
	}
	fh := s.dirs.Add(f)
	return &pb.OpenDirResponse{Fh: fh}, nil
}

func (s *FSServer) ReadDir(_ context.Context, req *pb.ReadDirRequest) (*pb.ReadDirResponse, error) {
	f, ok := s.dirs.Get(req.Fh)
	if !ok {
		return &pb.ReadDirResponse{Errno: int32(syscall.EBADF)}, nil
	}

	entries, err := f.ReadDir(-1)
	if err != nil {
		return &pb.ReadDirResponse{Errno: errnoVal(err)}, nil
	}

	var pbEntries []*pb.DirEntry
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		pbEntries = append(pbEntries, &pb.DirEntry{
			Name: e.Name(),
			Ino:  fsutil.Inode(info),
			Mode: uint32(info.Mode()),
		})
	}
	return &pb.ReadDirResponse{Entries: pbEntries}, nil
}

func (s *FSServer) ReleaseDir(_ context.Context, req *pb.ReleaseDirRequest) (*pb.ReleaseDirResponse, error) {
	err := s.dirs.Release(req.Fh)
	return &pb.ReleaseDirResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Mkdir(_ context.Context, req *pb.MkdirRequest) (*pb.MkdirResponse, error) {
	p := s.realPath(req.Path)
	err := os.Mkdir(p, os.FileMode(req.Mode))
	if err != nil {
		return &pb.MkdirResponse{Errno: errnoVal(err)}, nil
	}
	attr, err := fsutil.Lstat(p)
	if err != nil {
		return &pb.MkdirResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.MkdirResponse{Attr: attr}, nil
}

func (s *FSServer) Rmdir(_ context.Context, req *pb.RmdirRequest) (*pb.RmdirResponse, error) {
	err := os.Remove(s.realPath(req.Path))
	return &pb.RmdirResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Open(_ context.Context, req *pb.OpenRequest) (*pb.OpenResponse, error) {
	f, err := os.OpenFile(s.realPath(req.Path), int(req.Flags), 0)
	if err != nil {
		return &pb.OpenResponse{Errno: errnoVal(err)}, nil
	}
	fh := s.files.Add(f)
	return &pb.OpenResponse{Fh: fh}, nil
}

func (s *FSServer) Read(_ context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	f, ok := s.files.Get(req.Fh)
	if !ok {
		return &pb.ReadResponse{Errno: int32(syscall.EBADF)}, nil
	}
	buf := make([]byte, req.Size)
	n, err := f.ReadAt(buf, req.Offset)
	if n > 0 {
		return &pb.ReadResponse{Data: buf[:n]}, nil
	}
	if err != nil {
		return &pb.ReadResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.ReadResponse{}, nil
}

func (s *FSServer) Write(_ context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error) {
	f, ok := s.files.Get(req.Fh)
	if !ok {
		return &pb.WriteResponse{Errno: int32(syscall.EBADF)}, nil
	}
	n, err := f.WriteAt(req.Data, req.Offset)
	if err != nil {
		return &pb.WriteResponse{Errno: errnoVal(err), Written: uint32(n)}, nil
	}
	return &pb.WriteResponse{Written: uint32(n)}, nil
}

func (s *FSServer) Release(_ context.Context, req *pb.ReleaseRequest) (*pb.ReleaseResponse, error) {
	err := s.files.Release(req.Fh)
	return &pb.ReleaseResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Create(_ context.Context, req *pb.CreateRequest) (*pb.CreateResponse, error) {
	p := s.realPath(req.Path)
	f, err := os.OpenFile(p, int(req.Flags)|os.O_CREATE, os.FileMode(req.Mode))
	if err != nil {
		return &pb.CreateResponse{Errno: errnoVal(err)}, nil
	}
	fh := s.files.Add(f)
	attr, err := fsutil.Lstat(p)
	if err != nil {
		return &pb.CreateResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.CreateResponse{Fh: fh, Attr: attr}, nil
}

func (s *FSServer) Unlink(_ context.Context, req *pb.UnlinkRequest) (*pb.UnlinkResponse, error) {
	err := os.Remove(s.realPath(req.Path))
	return &pb.UnlinkResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Rename(_ context.Context, req *pb.RenameRequest) (*pb.RenameResponse, error) {
	err := os.Rename(s.realPath(req.OldPath), s.realPath(req.NewPath))
	return &pb.RenameResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Truncate(_ context.Context, req *pb.TruncateRequest) (*pb.TruncateResponse, error) {
	err := os.Truncate(s.realPath(req.Path), req.Size)
	return &pb.TruncateResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Chmod(_ context.Context, req *pb.ChmodRequest) (*pb.ChmodResponse, error) {
	err := os.Chmod(s.realPath(req.Path), os.FileMode(req.Mode))
	return &pb.ChmodResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Chown(_ context.Context, req *pb.ChownRequest) (*pb.ChownResponse, error) {
	err := fsutil.Lchown(s.realPath(req.Path), int(req.Uid), int(req.Gid))
	return &pb.ChownResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Utimens(_ context.Context, req *pb.UtimensRequest) (*pb.UtimensResponse, error) {
	err := fsutil.Utimens(s.realPath(req.Path), req.AtimeSec, int64(req.AtimeNsec), req.MtimeSec, int64(req.MtimeNsec))
	return &pb.UtimensResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) Symlink(_ context.Context, req *pb.SymlinkRequest) (*pb.SymlinkResponse, error) {
	err := os.Symlink(req.Target, s.realPath(req.LinkPath))
	if err != nil {
		return &pb.SymlinkResponse{Errno: errnoVal(err)}, nil
	}
	attr, err := fsutil.Lstat(s.realPath(req.LinkPath))
	if err != nil {
		return &pb.SymlinkResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.SymlinkResponse{Attr: attr}, nil
}

func (s *FSServer) Link(_ context.Context, req *pb.LinkRequest) (*pb.LinkResponse, error) {
	err := os.Link(s.realPath(req.OldPath), s.realPath(req.NewPath))
	if err != nil {
		return &pb.LinkResponse{Errno: errnoVal(err)}, nil
	}
	attr, err := fsutil.Lstat(s.realPath(req.NewPath))
	if err != nil {
		return &pb.LinkResponse{Errno: errnoVal(err)}, nil
	}
	return &pb.LinkResponse{Attr: attr}, nil
}

func (s *FSServer) Fsync(_ context.Context, req *pb.FsyncRequest) (*pb.FsyncResponse, error) {
	f, ok := s.files.Get(req.Fh)
	if !ok {
		return &pb.FsyncResponse{Errno: int32(syscall.EBADF)}, nil
	}
	err := f.Sync()
	return &pb.FsyncResponse{Errno: errnoVal(err)}, nil
}

func (s *FSServer) StatFs(_ context.Context, req *pb.StatFsRequest) (*pb.StatFsResponse, error) {
	return fsutil.StatFs(s.realPath(req.Path))
}
