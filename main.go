package main

import (
	"os"
	"fmt"
	"syscall"
	"reflect"
	"unsafe"
	"debug/elf"
)


const GDUMP = 6

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func main() {

	fmt.Println("VINICIO VALBUENA in .rodata")
	fmt.Printf("%x\n\n", "VINICIO VALBUENA in .rodata")

	el, err := elf.Open("/proc/self/exe")
	checkError(err)

	section := el.Section(".rodata")
	el.Close()

	pagesize := syscall.Getpagesize()

	// REF: http://refspecs.linuxfoundation.org/ELF/zSeries/lzsabi0_s390/c2077.html
	// Virtual Address     0x00400000
	offset := uintptr(section.Offset + 0x00400000)
	size   := uintptr(section.Size) + offset
	rodata := offset & -uintptr(pagesize)
	psize  := size - rodata

	fmt.Printf("pagesize            0x%06X\n", pagesize)
	fmt.Println(".rodata")
	fmt.Printf("           offset   0x%06X\n",   offset)
	fmt.Printf("           size     0x%06X\n",     size)
	fmt.Printf("           rodata   0x%06X\n",   rodata)
	fmt.Printf("           psize    0x%06X\n",    psize)
	fmt.Println()

	ptr := reflect.SliceHeader{
		Data:   rodata,
		Len:  int(psize),
		Cap:  int(psize),
	}

	addr := *(*[]byte)(unsafe.Pointer(&ptr))

	checkError(syscall.Mprotect(addr, syscall.PROT_READ))

	// $ objdump -sj .rodata tmp | less
	fmt.Println("DUMP PROGRAM", section.Name)
	for i, _ := range addr {
		fmt.Printf("%02x", addr[i])

		if i % 4 == 3 {
			fmt.Printf(" ")
		}


		if i % (4*GDUMP) == (4*GDUMP)-1 {
			fmt.Println()
		}
	}
	fmt.Println()
}
