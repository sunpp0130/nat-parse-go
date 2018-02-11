package main

import (
	"time"
	"flag"
	seelog "github.com/cihub/seelog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	layers "github.com/google/gopacket/layers"
	"runtime"
	//"strings"
	"fmt"
	"log"
        //"os"
	//"t"
	//"unicode"
)

var (
	device       string
	pcapFile	 string
	snapshot_len int32  = 1500
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	processorNumber int

	maxWorkers	int
	WorkerPoll	chan chan gopacket.Packet
	//natlog          *log.Logger
	//natLogPath	string
	pcapLinkType	int = -1

)

type Worker struct{
	WorkerPoll chan chan gopacket.Packet
	PacketChannel	chan gopacket.Packet
	quit 		chan bool
}

func newWorker(workerPool chan chan gopacket.Packet) Worker{
	return Worker{
		workerPool,
		make(chan gopacket.Packet),
		make(chan bool)}
	}
func (w Worker) Start() {
	go func() {
		for {
			w.WorkerPoll <- w.PacketChannel
			select {
			case packet := <-w.PacketChannel:
				//debug
				//continue
				analysis_packet(packet)
			case <-w.quit:
				return
			}

		}
	}()
}

func PayloadString(c []byte) string {
    	n := -1
    	m := 0
    	isspace := 0
    	for i, b := range c {
        	if b == 0 {
            		break
        	}
		if b == ' ' {
			isspace++
        	}
		if isspace == 10 {
			isspace = 0
			m = i
		} 
        	n = i
    	}
	//fmt.Printf("m is %d n is %d isspace is %d\n", m, n, isspace)
    	return string(c[m+1:n+1])
}

func analysis_packet(packet gopacket.Packet) {
	// Process packet here
	//fmt.Println(packet)

	defer func() {
		panicked := recover()

		if panicked != nil {
			fmt.Printf("%v\n", panicked)
			//log.Printf("cache size is %d\n", requestCache.lruCache.Len())
		}
	}()

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		fmt.Printf("ip layer missing")
		return
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		//fmt.Println("UDP layers detected")
		//ip := ipLayer.(*layers.IPv4)
		//udp := udpLayer.(*layers.UDP)
		//fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		//fmt.Println(udp.Payload)
		applicationLayer := packet.ApplicationLayer()
    		if applicationLayer != nil {
        		//fmt.Println("Application layer/Payload found.")
        		//log.Printf("%s\n", PayloadString(applicationLayer.Payload()))
        		seelog.Info(PayloadString(applicationLayer.Payload()))
    		}
	}
}

func main() {
	flag.StringVar(&device, "i", "eth0", "ether card name" )
	flag.StringVar(&pcapFile, "r", "", "pcap file name")
	flag.IntVar(&processorNumber, "p", runtime.NumCPU(), "number of processor to use")
	//flag.StringVar(&natLogPath, "o", "./", "log path")
	flag.Parse()

	maxWorkers = processorNumber

	WorkerPoll = make(chan chan gopacket.Packet, maxWorkers)

	if(processorNumber+2 > runtime.NumCPU()){
		processorNumber = runtime.NumCPU()
	}else{
		processorNumber +=2
	}
	runtime.GOMAXPROCS(processorNumber)

	//var natFileName = natLogPath + "/nat.log"

	for i:=0; i<maxWorkers;i++ {
		worker:=newWorker(WorkerPoll)
		worker.Start()
	}

	/*f, err := os.OpenFile(natFileName, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
    		//t.Fatalf("error opening file: %v", err)
		panic(err)
	}
	defer f.Close()
	
	log.SetOutput(f)*/

	logger, err := seelog.LoggerFromConfigAsFile("seelog.xml")
    
    	if err != nil {
        	fmt.Println("err parsing config log file", err)
        	return
    	}
    	seelog.ReplaceLogger(logger)
	defer seelog.Flush()

	/*go func(){
		dnsLog2 := lumberjack.Logger{
			Filename:   dnsFileName,
			MaxSize:    dnsLogSize, // megabytes after which new file is created
			MaxBackups: dnsLogMaxBak, // number of backups
			MaxAge:     0, //days
			LocalTime:	true,
		}

		for{
			s , _:=logbuffer.Get()
			b :=[]byte(s.(string))
			dnsLog2.Write(b)
			//dnsLog.Print(s)
		}
	}()*/

	if(pcapFile == ""){
		// Open device
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
		if err != nil {log.Fatal(err) }
		defer handle.Close()

		// Set filter
		var filter string = "udp and port 9514"
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Only capturing UDP port 9514 packets.")
	}else{
		// Open file instead of device
		handle, err = pcap.OpenOffline(pcapFile)
		if err != nil { log.Fatal(err) }
		defer handle.Close()
		fmt.Println("open pcap file ", pcapFile)
	}


	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeRaw) //for dnscap
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		packetChannel := <-WorkerPoll
		packetChannel <- packet
	}
}

/*func dealPcap(pcapFile string) {

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Println(err)
		finishedFiles.Remove(pcapFile)
		return
	}
	defer handle.Close()

	log.Println("processing pcap file ", pcapFile)

	var packetSource *gopacket.PacketSource
	// Use the handle as a packet source to process all packets
	if(pcapLinkType == -1 || pcapLinkType == 0){
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	}else{
		packetSource = gopacket.NewPacketSource(handle, (layers.LinkType)(pcapLinkType))
	}

	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {

		packetChannel := <-WorkerPoll
		packetChannel <- packet
	}

	log.Println("processing finished")
}*/
