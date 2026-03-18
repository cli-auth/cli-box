//go:build unix

package fsutil

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	pb "github.com/cli-auth/cli-box/proto"
)

func Lstat(path string) (*pb.FileAttr, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return nil, err
	}
	return &pb.FileAttr{
		Ino:       st.Ino,
		Size:      uint64(st.Size),
		Mode:      uint32(st.Mode),
		Nlink:     uint32(st.Nlink),
		Uid:       st.Uid,
		Gid:       st.Gid,
		AtimeSec:  st.Atim.Sec,
		MtimeSec:  st.Mtim.Sec,
		CtimeSec:  st.Ctim.Sec,
		AtimeNsec: int32(st.Atim.Nsec),
		MtimeNsec: int32(st.Mtim.Nsec),
		CtimeNsec: int32(st.Ctim.Nsec),
	}, nil
}

func Inode(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func Lchown(path string, uid, gid int) error {
	return unix.Lchown(path, uid, gid)
}

func Utimens(path string, atimeSec, atimeNsec, mtimeSec, mtimeNsec int64) error {
	ts := []unix.Timespec{
		{Sec: atimeSec, Nsec: atimeNsec},
		{Sec: mtimeSec, Nsec: mtimeNsec},
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, unix.AT_SYMLINK_NOFOLLOW)
}

func StatFs(path string) (*pb.StatFsResponse, error) {
	var buf unix.Statfs_t
	if err := unix.Statfs(path, &buf); err != nil {
		return &pb.StatFsResponse{Errno: int32(err.(syscall.Errno))}, nil
	}
	return &pb.StatFsResponse{
		Blocks:  buf.Blocks,
		Bfree:   buf.Bfree,
		Bavail:  buf.Bavail,
		Files:   buf.Files,
		Ffree:   buf.Ffree,
		Bsize:   uint32(buf.Bsize),
		Frsize:  uint32(buf.Bsize),
		Namelen: 255,
	}, nil
}
