package main

import (
    "fmt"
    "runtime"
    "runtime/debug"
    "time"

    "github.com/xjasonlyu/tun2socks/v2/bridge"
)

type stubEmitter struct{}

func (stubEmitter) EmitPacket(packet []byte, proto int32) error { return nil }

type stubNetwork struct{}

func (stubNetwork) TCPDial(host string, port int32, timeoutMillis int64) (int64, error) {
    return 0, fmt.Errorf("stub TCPDial")
}

func (stubNetwork) TCPWrite(handle int64, payload []byte) (int32, error) {
    return 0, fmt.Errorf("stub TCPWrite")
}

func (stubNetwork) TCPClose(handle int64) error {
    return nil
}

func (stubNetwork) UDPDial(host string, port int32) (int64, error) {
    return 0, fmt.Errorf("stub UDPDial")
}

func (stubNetwork) UDPWrite(handle int64, payload []byte) (int32, error) {
    return 0, fmt.Errorf("stub UDPWrite")
}

func (stubNetwork) UDPClose(handle int64) error {
    return nil
}

func printStats(tag string) {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    fmt.Printf("%s: alloc=%d total=%d sys=%d heapAlloc=%d heapSys=%d stack=%d gcSys=%d otherSys=%d\n",
        tag, m.Alloc, m.TotalAlloc, m.Sys, m.HeapAlloc, m.HeapSys, m.StackInuse, m.GCSys, m.OtherSys)
}

func main() {
    printStats("startup")
    engine, err := bridge.NewEngine(&bridge.Config{MTU: 1500}, stubEmitter{}, stubNetwork{})
    if err != nil {
        panic(err)
    }
    printStats("after NewEngine")
    if err := engine.Start(); err != nil {
        panic(err)
    }
    printStats("after Start")
    time.Sleep(500 * time.Millisecond)
    runtime.GC()
    printStats("after GC")
    debug.FreeOSMemory()
    printStats("after FreeOSMemory")
    engine.Stop()
    printStats("after Stop")
}
