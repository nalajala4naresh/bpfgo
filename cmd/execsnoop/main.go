package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ./bpf/execsnoop.bpf.c -- -I../../headers

var (
	ErrKeyNotExist      = errors.New("next key: key does not exist")
	ErrKeyExist         = errors.New("key already exists")
	ErrIterationAborted = errors.New("iteration aborted")
	ErrMapIncompatible  = errors.New("map spec is incompatible with existing map")
)

func main() {

	var (
		printTime      = flag.Bool("time", false, "include the time of the event on output (HH:MM:SS)")
		printTimestamp = flag.Bool("timestamp", false, "include the time of the event in seconds on output, counting from the first event seen")
		printUID       = flag.Bool("print-uid", false, "include UID on output")
	)
	flag.Parse()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load and assign the bpf objects to programs

	bpfObjs := &bpfObjects{}
	err := loadBpfObjects(bpfObjs, nil)

	if err != nil {
		log.Fatalf(" Unable to load objects into kernel on error %s", err)
	}
	defer bpfObjs.Close()

	traceEntrylink, err := link.Tracepoint("syscalls", "sys_enter_execve", bpfObjs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("Attaching the Program to sys_enter_execve failed %s", err)
	}

	defer traceEntrylink.Close()

	traceExitlink, err := link.Tracepoint("syscalls", "sys_exit_execve", bpfObjs.TracepointSyscallsSysExitExecve, nil)
	if err != nil {
		log.Fatalf("Attaching the Program to sys_exit_execve failed %s", err)
	}

	defer traceExitlink.Close()

	log.Println("Waiting for events..")
	rd, err := perf.NewReader(bpfObjs.Events, os.Getpagesize())
	if err != nil {
		log.Printf("failed to create perf event reader: %v", err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	startTime := time.Now()

	printHeader(os.Stdout, *printTime, *printTimestamp, *printUID)

	for {

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			log.Printf("failed to read from perf ring buffer: %v", err)
		}

		if record.LostSamples != 0 {
			log.Printf("ring event perf buffer is full, dropped %d samples", record.LostSamples)
			continue
		}

		var e event
		err = binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&e,
		)
		if err != nil {
			log.Printf("failed to parse perf event: %v", err)
			continue
		}

		printEvent(os.Stdout, &e, record.RawSample[eventSize:], startTime, *printTime, *printTimestamp, *printUID)

	}

}
