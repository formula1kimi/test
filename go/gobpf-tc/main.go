package main

import (
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("get link error: %s", err)
	}
	var targetLink netlink.Link
	for _, link := range links {
		fmt.Printf("%d: [%s]%s, %s\n", link.Attrs().Index, link.Type(), link.Attrs().Name, link.Attrs().HardwareAddr.String())
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			log.Fatal(err)
		}
		if link.Attrs().Name == "eth1" {
			targetLink = link
		}
		for _, addr := range addrs {
			mask, _ := addr.IPNet.Mask.Size()
			fmt.Printf("  %s/%d\n", addr.IPNet.IP, mask)
		}
	}
	if targetLink == nil {
		log.Fatalf("Can not find target link eth1")
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: targetLink.Attrs().Index,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	}
	qdisc := netlink.NewHtb(attrs)

	// remove previous same qdisc if there is.
	err = netlink.QdiscDel(qdisc)
	if err != nil {
		log.Println("remove old qdisc error: %s", err)
	}

	qdisc.Rate2Quantum = 5
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalf("can not add htb qdisc: %s", err)
	}

	classattrs := netlink.ClassAttrs{
		LinkIndex: targetLink.Attrs().Index,
		Parent:    netlink.MakeHandle(0x1, 0),
		Handle:    netlink.MakeHandle(0x1, 1),
	}

	htbclassattrs := netlink.HtbClassAttrs{
		Rate:    10 * 1024 * 1024,
		Ceil:    10 * 1024 * 1024,
		Buffer:  1024 * 1024,
		Cbuffer: 1024 * 1024,
		Prio:    5,
		Quantum: 10000,
	}

	class := netlink.NewHtbClass(classattrs, htbclassattrs)
	if err := netlink.ClassAdd(class); err != nil {
		log.Fatalf("can not create htb class: %s", err)
	}

	filterattrs := netlink.FilterAttrs{
		LinkIndex: targetLink.Attrs().Index,
		Parent:    netlink.MakeHandle(1, 0),
		Handle:    netlink.MakeHandle(100, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	bpfModule, err := LoadBpf("bpf/paitc_bpf_classifier.o")
	if err != nil {
		log.Fatalf("load ebpf object file error: %s:", err)
	}
	defer bpfModule.Close()

	prog, err := bpfModule.GetProgram("cls_main")
	if err != nil {
		log.Fatalf("get program error: %s:", err)
	}

	progFd := int(prog.GetFd())
	progType := prog.GetType()
	log.Printf("bpf program fd = %d, type = %d", progFd, progType)

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           progFd,
		Name:         "classifier",
		ClassId:      1,
		DirectAction: false,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatal("Can not add filter: %s", err)
	}

	netClsMap, err := bpfModule.GetMap("net_cls_map")
	if err != nil {
		log.Fatalf("get tsm map error: %s:", err)
	}
	var netcls uint32 = 1000
	var classid uint32 = netlink.MakeHandle(0x01, 0x01)
	err = netClsMap.Update(netcls, classid)
	if err != nil {
		log.Fatalf("set net cls map error: %s:", err)
	}
	log.Printf("set net cls map: %d -> %d", netcls, classid)

}

func LoadBpf(filepath string) (*bpf.Module, error) {
	bpfModule, err := bpf.NewModuleFromFile(filepath)
	if err != nil {
		return nil, err
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		return nil, err
	}

	return bpfModule, nil
	/*
		tsm, err := bpfModule.GetMap("tcp_sport_map")
		if err != nil {
			log.Fatalf("get tsm map error: %s:", err)
		}
		var key uint32 = 1000
		var value uint32 = 1200
		err = tsm.Update(key, value)
		if err != nil {
			log.Fatalf("set tsm map error: %s:", err)
		}
		data, err := tsm.GetValue(key)
		if err != nil {
			log.Fatalf("try get tsm map error: %s:", err)
		}
		v := binary.LittleEndian.Uint32(data[0:4])
		log.Printf("get tsm map data: %d -> %d", 1000, v)
	*/
}
