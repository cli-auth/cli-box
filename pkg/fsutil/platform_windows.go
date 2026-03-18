package fsutil

import (
	"os"
	"time"

	pb "github.com/cli-auth/cli-box/proto"
)

func Lstat(path string) (*pb.FileAttr, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	mtime := info.ModTime()
	return &pb.FileAttr{
		Size:      uint64(info.Size()),
		Mode:      uint32(info.Mode()),
		Nlink:     1,
		MtimeSec:  mtime.Unix(),
		MtimeNsec: int32(mtime.Nanosecond()),
		AtimeSec:  mtime.Unix(),
		AtimeNsec: int32(mtime.Nanosecond()),
		CtimeSec:  mtime.Unix(),
		CtimeNsec: int32(mtime.Nanosecond()),
	}, nil
}

func Inode(info os.FileInfo) uint64 {
	return 0
}

func Lchown(path string, uid, gid int) error {
	return nil
}

func Utimens(path string, atimeSec, atimeNsec, mtimeSec, mtimeNsec int64) error {
	atime := time.Unix(atimeSec, atimeNsec)
	mtime := time.Unix(mtimeSec, mtimeNsec)
	return os.Chtimes(path, atime, mtime)
}

func StatFs(path string) (*pb.StatFsResponse, error) {
	return &pb.StatFsResponse{
		Bsize:   4096,
		Frsize:  4096,
		Namelen: 255,
	}, nil
}
