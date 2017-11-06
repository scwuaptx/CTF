# Baby FS

### Vulnerability

+ Heap overflow
	+ If you open `/dev/stdin`, it would cause heap overflow. Because the getfilesize would return -1. That is, you can read many data from `stdin`

```
size_t getfilesize(FILE *fp){
    size_t size = 0 ;
    fseek(fp, 0, SEEK_END) ;
    size = ftell(fp) ;
    fseek(fp, 0, SEEK_SET) ;
    return size ;
}
``` 


### Exploitation


+ Read from anywhere 
	+ Use heap overflow to overwrite FILE struture of logfile.
		+ Change the _fileno to stdout then you will get leak.
		+ You can use it to leak libc.

+ Write to anywhere
	+ Change the buffer of FILE struture to where you want to write
	+ Change the _fileno to stdin so that you can read from stdin.

+ Control the flow :)
+ More detail
	+ [Play with FILE Structure](http://4ngelboy.blogspot.tw/2017/11/play-with-file-structure-yet-another.html) 
+ Note 
	+ The challenge is running with socat, some charater would be truncated. You need to use `"\x16"` to escape. 
 	 
+ Exploit
	+ [exp.py](exp.py)
