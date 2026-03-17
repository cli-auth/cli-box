package fsutil

import (
	"golang.org/x/sys/unix"

	pb "github.com/cli-auth/cli-box/proto"
)

func StatToAttr(st *unix.Stat_t) *pb.FileAttr {
	return &pb.FileAttr{
		Ino:       st.Ino,
		Size:      uint64(st.Size),
		Mode:      st.Mode,
		Nlink:     uint32(st.Nlink),
		Uid:       st.Uid,
		Gid:       st.Gid,
		AtimeSec:  st.Atim.Sec,
		MtimeSec:  st.Mtim.Sec,
		CtimeSec:  st.Ctim.Sec,
		AtimeNsec: int32(st.Atim.Nsec),
		MtimeNsec: int32(st.Mtim.Nsec),
		CtimeNsec: int32(st.Ctim.Nsec),
	}
}
