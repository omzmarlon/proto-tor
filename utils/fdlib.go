/*

This package specifies the API to the failure detector library to be
used in assignment 1 of UBC CS 416 2018W1.

You are *not* allowed to change the API below. For example, you can
modify this file by adding an implementation to Initialize, but you
cannot change its API.

*/

package utils

import (
	"bytes"
	"encoding/gob"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)
import "time"

//////////////////////////////////////////////////////
// Define the message types fdlib has to use to communicate to other
// fdlib instances. We use Go's type declarations for this:
// https://golang.org/ref/spec#Type_declarations

// Heartbeat message.
type HBeatMessage struct {
	EpochNonce uint64 // Identifies this fdlib instance.
	SeqNum     uint64 // Monotonically increasing.
}

// An ack message; response to a heartbeat.
type AckMessage struct {
	HBEatEpochNonce uint64 // Copy of what was received in the heartbeat.
	HBEatSeqNum     uint64 // Copy of what was received in the heartbeat.
}

// Notification of a failure, signal back to the client using this
// library.
type FailureDetected struct {
	UDPIpPort string    // The IP:port of the failed node.
	Timestamp time.Time // The time when the failure was detected.
}

/// Custom structs

// Represents details for monitoring a remote node
type RemoteNodeMonitorInfo struct {
	LostMsgThresh uint8
	Conn          *net.UDPConn
	NumFailedAcks uint8
	AvgRTT        time.Duration
	ShouldMonitor bool
	sync.Mutex
}

// Contains info about all remote nodes
type RemoteNodes struct {
	Map map[string]*RemoteNodeMonitorInfo
}

// Contains info about all outstanding heartbeats for a certain node
type Heartbeats struct {
	hbeats *map[uint64]*HeartbeatInfo
}

// Contains info about a recently sent heartbeat
type HeartbeatInfo struct {
	TimeSent time.Time
}

////////////////////////////////////////////////////// Global Vars
var INIT_RTT time.Duration

const PKT_SIZE = 1024

var initialized bool

const DEBUG = false

////////////////////////////////////////////////////// Fdlib interface

// An FD interface represents an instance of the fd
// library. Interfaces are everywhere in Go:
// https://gobyexample.com/interfaces
type FD interface {
	// Tells the library to start responding to heartbeat messages on
	// a local UDP IP:port. Can return an error that is related to the
	// underlying UDP connection.
	StartResponding(LocalIpPort string) (err error)

	// Tells the library to stop responding to heartbeat
	// messages. Always succeeds.
	StopResponding()

	// Tells the library to start monitoring a particular UDP IP:port
	// with a specific lost messages threshold. Can return an error
	// that is related to the underlying UDP connection.
	AddMonitor(LocalIpPort string, RemoteIpPort string, LostMsgThresh uint8) (err error)

	// Tells the library to stop monitoring a particular remote UDP
	// IP:port. Always succeeds.
	RemoveMonitor(RemoteIpPort string)

	// Tells the library to stop monitoring all nodes.
	StopMonitoring()
}

type Fdlib struct {
	NotifyCh   chan FailureDetected
	EpochNonce uint64

	// For responding to heartbeats
	RespServConn net.PacketConn
	Responding   bool

	// For monitoring nodes
	NodesToMonitor RemoteNodes // indexed by RemoteIpPort

	// For logging everything about the library
	Log *log.Logger
}

func (fd *Fdlib) StartResponding(LocalIpPort string) (err error) {
	defer func() {
		if err != nil {
			fd.Println(err)
		}
	}()
	if fd.Responding {
		return errors.New("already responding")
	}

	// Resolve local address
	laddr, err := net.ResolveUDPAddr("udp", LocalIpPort)
	if err != nil {
		return
	}

	// Setup UDP server
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return
	}

	// Save the connection
	fd.RespServConn = conn

	go func() {
		for {
			// Listen to incoming connections
			var recvBuf [PKT_SIZE]byte
			bytesRead, retAddr, err := fd.RespServConn.ReadFrom(recvBuf[:])
			if err != nil {
				// FIXME is there a better way of checking this? Ugh!
				if strings.Contains(err.Error(), "use of closed network connection") {
					// Stop listening to incoming connections
					return
				}
				fd.Println("Error: Could not read an incoming connection,", err)
				return // Error occurred while reading, should not happen
			}

			// Decode the heartbeat message
			bufDecoder := bytes.NewBuffer(recvBuf[:bytesRead])
			decoder := gob.NewDecoder(bufDecoder)
			var hbeatMsg HBeatMessage
			err = decoder.Decode(&hbeatMsg)
			if err != nil {
				fd.Println("Error: Could not decode incoming heartbeat msg")
				continue
			}

			// Encode the ACK
			var hbeatAck = AckMessage{
				HBEatEpochNonce: hbeatMsg.EpochNonce,
				HBEatSeqNum:     hbeatMsg.SeqNum,
			}
			var buffer bytes.Buffer
			encoder := gob.NewEncoder(&buffer)
			encoder.Encode(hbeatAck)

			// Send the ACK
			_, err = fd.RespServConn.WriteTo(buffer.Bytes(), retAddr)
			if err != nil {
				fd.Println("Error: could not send an ACK")
				continue
			}
			fd.Println("Info: Successfully sent an ACK for ", hbeatAck.HBEatSeqNum)
		}
	}()
	fd.Responding = true
	return nil
}

func (fd *Fdlib) StopResponding() {
	// Stop listening to incoming UDP connections
	if fd.RespServConn != nil {
		fd.RespServConn.Close()
		fd.Responding = false
	}
}

func (fd *Fdlib) AddMonitor(LocalIpPort, RemoteIpPort string, LostMsgThresh uint8) (err error) {
	remoteNode, found := fd.NodesToMonitor.Map[RemoteIpPort]
	if found {
		remoteNode.LostMsgThresh = LostMsgThresh
		if remoteNode.ShouldMonitor {
			// we are already monitoring it
			return
		}
		remoteNode.ShouldMonitor = true
	} else { // Need to add the details about remote node

		// Create an entry for node that we will monitor
		remoteNode = &RemoteNodeMonitorInfo{
			LostMsgThresh: LostMsgThresh,
			AvgRTT:        INIT_RTT,
			NumFailedAcks: 0,
			ShouldMonitor: true,
		}
		// Add the node to our map of nodes we monitor
		fd.NodesToMonitor.Map[RemoteIpPort] = remoteNode
	}
	defer func() {
		if err != nil { // If an error occurred, remove the node from our list
			remoteNode.ShouldMonitor = false
			remoteNode.Conn = nil
		}
	}()

	// Resolve remote address
	remoteAddr, err := net.ResolveUDPAddr("udp", RemoteIpPort)
	if err != nil {
		return
	}

	// Resolve local address
	localAddr, err := net.ResolveUDPAddr("udp", LocalIpPort)
	if err != nil {
		return
	}
	// Get a connection to remote node
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return
	}

	remoteNode.Conn = conn

	// Initialize monitoring of a node
	go func() {
		// Keeps info about heartbeats
		mp := make(map[uint64]*HeartbeatInfo)
		hb := &Heartbeats{
			hbeats: &mp,
		}

		var hbeatNum uint64 = 0

		// Start sending heartbeats
		keepMonitoring := true
		for keepMonitoring {
			keepMonitoring = fd.sendHeartbeatMsg(RemoteIpPort, remoteNode, hb, hbeatNum)
			hbeatNum++
		}
		fd.removeMonitorHelper(RemoteIpPort)
	}()
	return
}

func (fd *Fdlib) RemoveMonitor(RemoteIpPort string) {
	fd.removeMonitorHelper(RemoteIpPort)
}

func (fd *Fdlib) StopMonitoring() {
	for key := range fd.NodesToMonitor.Map {
		fd.removeMonitorHelper(key)
	}
}

// Helper method for ceasing to monitor a node. Should be called after the NodesToMonitor lock has been obtained
func (fd *Fdlib) removeMonitorHelper(RemoteIpPort string) {
	info, found := fd.NodesToMonitor.Map[RemoteIpPort]
	if !found {
		return
	}
	info.Lock()
	defer info.Unlock()
	if info.Conn != nil {
		info.Conn.Close()
		info.Conn = nil
	}
	info.NumFailedAcks = 0
	info.ShouldMonitor = false
}

// Sends one heartbeat message and waits for ACK for a fixed predetermined time
func (fd *Fdlib) sendHeartbeatMsg(remoteIpPort string, info *RemoteNodeMonitorInfo, hb *Heartbeats, hbeatNum uint64) (keepMonitoring bool) {
	info.Lock()
	defer info.Unlock()

	// Locate info about remote node
	if !info.ShouldMonitor {
		fd.Println("HBEAT: Don't need to monitor the node anymore")
		return false
	}

	// Generate random UUID for the heartbeat
	hbeatUUID := hbeatNum

	// Create a heartbeat message
	hbeatMsg := HBeatMessage{
		EpochNonce: fd.EpochNonce,
		SeqNum:     hbeatUUID,
	}

	// Encode heart beat message
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(hbeatMsg)
	if err != nil {
		// Should not happen
		fd.Println("HBEAT: Error: Failed to marshall heartbeat message")
		return true
	}

	// Start timing
	hbeatSent := time.Now()

	// Add to heartbeats map
	(*hb.hbeats)[hbeatUUID] = &HeartbeatInfo{
		TimeSent: hbeatSent,
	}

	fd.Println("HBEAT: Sending", hbeatUUID, "at", hbeatSent, "to", remoteIpPort)

	hbeatAcked := false

	// Send heartbeat message
	_, err = info.Conn.Write(buffer.Bytes())
	if err == nil {
		// Set the deadline for read
		info.Conn.SetReadDeadline(time.Now().Add(info.AvgRTT))
		// Receive any pending ACKs
		var buf [PKT_SIZE]byte
		bytesRead, err := info.Conn.Read(buf[:])
		if err == nil {
			fd.Println("Read", bytesRead, "bytes")
			// Decode the ACK message
			ackMsg, ok := fd.decodeAckMessage(buf, bytesRead)
			if ok {
				// Note the time when we received the ACK
				ackRecvedTime := time.Now()
				hbeat, found := (*hb.hbeats)[ackMsg.HBEatSeqNum]
				if found {
					hbeatAcked = true
					fd.updateRTT(info, hbeat.TimeSent, ackRecvedTime, ackMsg.HBEatSeqNum, hb.hbeats)
				}
			}
		}
	}

	// See if we need to catch up on any other ACKs
	for {
		info.Conn.SetReadDeadline(time.Now().Add(1 * time.Nanosecond))
		var buf [PKT_SIZE]byte
		bytesRead, err := info.Conn.Read(buf[:])
		if err != nil {
			break
		}
		// Decode the ACK message
		ackMsg, ok := fd.decodeAckMessage(buf, bytesRead)
		if !ok {
			fd.Println("Err trying to decode ack message")
			continue
		}

		// Note the time when we received the ACK
		ackRecvedTime := time.Now()
		hbeat, found := (*hb.hbeats)[ackMsg.HBEatSeqNum]
		if found {
			fd.Println("Receiving older ACKs", ackMsg.HBEatSeqNum)
			fd.updateRTT(info, hbeat.TimeSent, ackRecvedTime, ackMsg.HBEatSeqNum, hb.hbeats)
			hbeatAcked = true
		}
	}

	if !hbeatAcked {
		info.NumFailedAcks++
		fd.Println("HBEAT: Did not get any new ACKs :( just sent out", hbeatUUID, ". Num lost ACKs so far: ", info.NumFailedAcks)
		if info.NumFailedAcks == info.LostMsgThresh {
			// Stop monitoring this node
			fd.Println("Num failed acks", info.NumFailedAcks)
			fd.Println("Error: Lets stop monitoring this node", remoteIpPort)
			fd.NotifyCh <- FailureDetected{
				UDPIpPort: remoteIpPort,
				Timestamp: time.Now(),
			}
			return
		}
	}
	return true
}

func (fd *Fdlib) decodeAckMessage(buf [PKT_SIZE]byte, bytesRead int) (ackMsg AckMessage, success bool) {
	bufDecoder := bytes.NewBuffer(buf[:bytesRead])
	decoder := gob.NewDecoder(bufDecoder)
	err := decoder.Decode(&ackMsg)
	if err != nil || ackMsg.HBEatEpochNonce != fd.EpochNonce {
		return
	}
	return ackMsg, true
}

// Helper for updating RTT of the node
// Should only be called when the lock is held
func (fd *Fdlib) updateRTT(info *RemoteNodeMonitorInfo, timeSent, timeRecv time.Time, uuid uint64, hbeats *map[uint64]*HeartbeatInfo) {
	currRTT := timeRecv.Sub(timeSent)
	total := uint64(currRTT.Nanoseconds()) + uint64(info.AvgRTT.Nanoseconds())
	avg := total / 2
	info.AvgRTT = time.Duration(int64(avg))
	info.NumFailedAcks = 0
	delete(*hbeats, uuid)

	fd.Println("Hbeat", uuid, " took ", currRTT)
	fd.Println("Avg rtt:", info.AvgRTT)
}

func (fd *Fdlib) Println(v ...interface{}) {
	if DEBUG {
		fd.Log.Println(v...)
		// If you don't want to print to a log, comment out the line above and uncomment the line below
		// fmt.Println(v...)
	}
}

// The constructor for a new FD object instance. Note that notifyCh
// can only be received on by the client that receives it from
// initialize:
// https://www.golang-book.com/books/intro/10
func Initialize(EpochNonce uint64, ChCapacity uint8) (fd FD, notifyCh <-chan FailureDetected, err error) {
	if initialized {
		return nil, nil, errors.New("unimplemented")
	}

	ch := make(chan FailureDetected, ChCapacity)
	nodes := RemoteNodes{
		Map: make(map[string]*RemoteNodeMonitorInfo),
	}

	// For logging purposes
	nm := "Log" + strconv.FormatUint(EpochNonce, 10) + ".log"
	file, err := os.OpenFile(nm, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, nil, err
	}

	logger := log.New(file, "", log.Lmicroseconds)

	fdlib := &Fdlib{
		EpochNonce:     EpochNonce,
		NotifyCh:       ch,
		NodesToMonitor: nodes,
		Log:            logger,
		Responding:     false,
	}

	initialized = true
	fd = fdlib
	INIT_RTT = time.Duration(3 * time.Second)
	return fd, ch, nil
}
