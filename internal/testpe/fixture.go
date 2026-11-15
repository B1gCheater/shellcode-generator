// Package testpe supplies header-only data for static-parser regression tests.
// The fixtures contain no executable program and are never loaded or executed.
package testpe

import "encoding/binary"

// Image returns a minimal PE metadata fixture and its data-directory offset.
func Image(x86, dll bool) ([]byte, int) {
	b := make([]byte, 1024)
	u16 := func(off int, n uint16) { binary.LittleEndian.PutUint16(b[off:], n) }
	u32 := func(off int, n uint32) { binary.LittleEndian.PutUint32(b[off:], n) }
	u16(0, 0x5a4d)
	u32(0x3c, 0x80)
	u32(0x80, 0x4550)
	machine, magic, optionalSize, dir := uint16(0x8664), uint16(0x20b), 240, 112
	if x86 {
		machine, magic, optionalSize, dir = 0x14c, 0x10b, 224, 96
	}
	file, opt := 0x84, 0x98
	u16(file, machine)
	u16(file+2, 1)
	u16(file+16, uint16(optionalSize))
	chars := uint16(0x2)
	if dll {
		chars |= 0x2000
	}
	u16(file+18, chars)
	u16(opt, magic)
	u32(opt+16, 0x1000)
	if x86 {
		u32(opt+28, 0x400000)
	} else {
		binary.LittleEndian.PutUint64(b[opt+24:], 0x140000000)
	}
	u32(opt+32, 0x1000)
	u32(opt+36, 0x200)
	u32(opt+56, 0x2000)
	u32(opt+60, 0x200)
	u16(opt+68, 3)
	u32(opt+dir-4, 16)
	dir += opt
	u32(dir+5*8, 0x1100)
	u32(dir+5*8+4, 12)
	section := opt + optionalSize
	copy(b[section:], ".text")
	u32(section+8, 0x200)
	u32(section+12, 0x1000)
	u32(section+16, 0x200)
	u32(section+20, 0x200)
	u32(section+36, 0x60000020)
	return b, dir
}
