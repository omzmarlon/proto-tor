package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/DistributedClocks/GoVector/govec"
)

const MSG_SIZE = 4 // 4 bytes in size

func TCPRead(from *net.TCPConn, vecLogger *govec.GoLog, vecMsg string) ([]byte, error) {
	// Reading message size
	sizeBuf := make([]byte, 0)
	sReadCount := MSG_SIZE
	sReadBuf := make([]byte, 1) // read one byte at a time
	for {
		s, err := from.Read(sReadBuf)
		if err != nil {
			return nil, err
		}
		sReadCount--
		sizeBuf = append(sizeBuf, sReadBuf[0:s]...)
		if sReadCount == 0 {
			break
		}
	}

	mlen := binary.LittleEndian.Uint32(sizeBuf)

	actlen := int(mlen)
	fmt.Println("**Networking**: Expected message size:", actlen)

	// Reading acutal message
	bytes := make([]byte, 0)
	chunkCap := 1024
	chunk := make([]byte, chunkCap)

	sizeMsg := 0

	for {
		size, rerr := from.Read(chunk)
		if rerr != nil {
			if rerr != io.EOF {
				return nil, rerr
			}

			break
		}
		bytes = append(bytes, chunk[:size]...)
		sizeMsg += size

		if sizeMsg >= actlen {
			break
		}
	}

	if sizeMsg != actlen {
		return nil, errors.New("msg size wrong")
	}
	fmt.Printf("**Networking**: Read total: %d bytes\n", sizeMsg)

	var results []byte
	vecLogger.UnpackReceive(vecMsg, bytes, &results, govec.GetDefaultLogOptions())
	return results, nil
}

func TCPWrite(to *net.TCPConn, payload []byte, vecLogger *govec.GoLog, vecMsg string) (int, error) {
	loggedPayload := vecLogger.PrepareSend(vecMsg, payload, govec.GetDefaultLogOptions())

	b := make([]byte, MSG_SIZE)
	binary.LittleEndian.PutUint32(b, uint32(len(loggedPayload)))

	_, _ = to.Write(b)
	fmt.Printf("**Networking**: write total: %d bytes\n", uint32(len(loggedPayload)))
	return to.Write(loggedPayload)
}
