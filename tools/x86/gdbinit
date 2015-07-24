source ~/peda/peda.py
source ~/pwngdbx86.py
define libc
	python putlibc()
end
define ld
	python putld()
end
define off
	python putoff("$arg0")
end
define got
	python got()
end
define dyn
	python dyn()
end
define rdbg
	target remote localhost:1234
end
define findcall
	python putfindcall("$arg0")
end

define bcall
	python bcall("$arg0")
end
