package main

import (
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	pb "github.com/cli-auth/cli-box/proto"
)

// MountFUSE mounts a FUSE filesystem at mountpoint, backed by the given
// FileSystem gRPC client. Returns the fuse.Server for lifecycle management.
func MountFUSE(mountpoint string, client pb.FileSystemClient) (*fuse.Server, error) {
	root := &RemoteNode{client: client, path: ""}
	return fs.Mount(mountpoint, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			AllowOther: false,
			FsName:     "cli-box",
			Name:       "cli-box",
		},
	})
}

func UnmountFUSE(server *fuse.Server) error {
	return server.Unmount()
}
