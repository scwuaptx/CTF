;/opt/gbdk/bin/lcc -o aaaaaaaaaaaaaaaa.gb gameboy.s
_main::
	ld c,#0x90
	ld a,#0x90
	call gg
	nop
	nop
	nop
	nop
	
	ld bc,#9
	ld a,(bc)
	add a,#0x1
	ld (9),a
	ld a,#0x10
	ld (8),a
	ld bc,#10
	ld a,(bc)
	add a,#2
	ld (10),a
	ld a,#0x1
	ld (0xff46),a

	ld bc,#9
	ld a,(bc)
	add a,#0x4
	ld (9),a
	ld bc,#10
	ld a,(bc)
	sub a,#1
	ld (10),a
	ld a,#3
	ld (0xff46),a


	ld bc,#9
	ld a,(bc)
	add a,#0x1
	ld (9),a
	ld a,#0
	ld (0xff46),a
	
	ld bc,#9
	ld a,(bc)
	sub a,#0x4
	ld (9),a
	ld a,#0
	ld (0xff46),a

	ld bc,#10
	ld a,(bc)
	sub a,#2
	ld (10),a
	
	ld bc,#2
	ld a,(bc)
	add a,#2
	ld (2),a
		

	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

gg :
	.byte 0xed
	ret
	
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	ld bc,#0xdac0
	ld a,(bc)
	ld (0x90),a
	ld bc,#0xdac1
	ld a,(bc)
	ld (0x91),a
	ld bc,#0xdac2
	ld a,(bc)
	ld (0x92),a
	ld bc,#0xdac3
	ld a,(bc)
	ld (0x93),a
	ld bc,#0xdac4
	ld a,(bc)
	ld (0x94),a
	ld bc,#0xdac5
	ld a,(bc)
	ld (0x95),a
	nop
	ld bc,#0x5aa0
	ld a,(bc)
	ld (0x98),a
	ld bc,#0x5aa1
	ld a,(bc)
	ld (0x99),a
	ld bc,#0x5aa2
	ld a,(bc)
	ld (0x9a),a
	ld bc,#0x5aa3
	ld a,(bc)
	ld (0x9b),a
	ld bc,#0x5aa4
	ld a,(bc)
	ld (0x9c),a
	ld bc,#0x5aa5
	ld a,(bc)
	ld (0x9d),a
	nop
	ld a,#0x68
	ld (0x40),a
	ld a,#0x3
	ld (0x41),a
	nop
	ld a,#0
	ld (0xff46),a
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	ld bc,#0x90
	ld a,(bc)
	add a,#0x45
	ld (0x8),a
	ld bc,#0x91
	ld a,(bc)
	add a,#0x30
	ld (0x9),a
	ld bc,#0x92
	ld a,(bc)
	add a,#0x20
	ld (0xa),a
	ld bc,#0x93
	ld a,(bc)
	ld (0xb),a
	ld bc,#0x94
	ld a,(bc)
	ld (0xc),a
	ld bc,#0x95
	ld a,(bc)
	ld (0xd),a
	nop
	ld bc,#0x98
	ld a,(bc)
	sub a,#0x04
	ld (0x800),a
	ld bc,#0x99
	ld a,(bc)
	sub a,#0x43
	ld (0x801),a
	ld bc,#0x9a
	ld a,(bc)
	sub a,#0x36
	ld (0x802),a
	ld bc,#0x9b
	ld a,(bc)
	ld (0x803),a
	ld bc,#0x9c
	ld a,(bc)
	ld (0x804),a
	ld bc,#0x9d
	ld a,(bc)
	ld (0x805),a
	ld a,#0
	ld (0x806),a
	ld a,#0
	ld (0x807),a
	
	nop
	nop
	nop
	nop
	nop
	ld a,#8
	ld (0xff46),a
	ld (0x44),a
