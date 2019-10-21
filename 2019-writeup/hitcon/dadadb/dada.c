#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>
#include <windows.h>
#define KEY_SIZE 0x40
HANDLE hHeap = NULL;
void init_proc() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	_setmode(_fileno(stdout), O_BINARY);
	_setmode(_fileno(stdin), O_BINARY);
	hHeap = HeapCreate(HEAP_GROWABLE, 0, 0);
}

void* hcalloc(size_t cnt,size_t size) {
	return HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size*cnt);
}

void hfree(void* ptr) {
	HeapFree(hHeap, 0, ptr);
}
void read_input(char* buf, size_t size) {
	HANDLE hStdin;
	hStdin = GetStdHandle(STD_INPUT_HANDLE);
	BOOL ret;
	DWORD rw;
	ret = ReadFile(hStdin, buf, size, &rw, NULL);

	if (!ret) {
		puts("read error");
		_exit(1);
	}
	if (buf[rw - 1] == '\x0a')
		buf[rw - 1] = '\x00';
	if (buf[rw - 2] == '\x0d')
		buf[rw - 2] = '\x00';
}

long long read_long() {
	char buf[0x10];
	long long choice;
	read_input(buf, 0x10);
	choice = atoll(buf);
	return choice;
}


void login_menu() {
	printf(">> ");
}

struct node{
	char* data;
	size_t size;
	char key[KEY_SIZE+1];
	struct node* next;

};

struct node* table[256];
bool is_login = false;
char user[0x20];
char pass[0x20];
FILE* fp = NULL;
void menu() {
	printf("%s@db>> ", user);
}
void login() {
	char* ret = NULL;
	char buf[0x100];
	char cmpbuf[0x30];
	memset(user, 0, 0x20);
	memset(pass, 0, 0x20);
	memset(cmpbuf, 0, 0x20);

	printf("User:");
	read_input(user, 0x20);
	printf("Password:");
	read_input(pass, 0x20);
	memset(buf, 0, 0x100);

	if (!fp) {
		fopen_s(&fp,"user.txt", "r");
		if (!fp)
			_exit(0);
	}
	fread(buf, 0x100, 0x1, fp);
	fseek(fp, 0, SEEK_SET);
	snprintf(cmpbuf,0x20,"%s:", user);
	ret = strstr(buf, cmpbuf);
	if (ret) {
		ret = strchr(ret, ':');
		if (!ret) {
			puts("Error!");
		}
		else {
			if (!strncmp(ret + 1, pass, strlen(pass))) {
				is_login = true;
				puts("login success!");
			}
			else {
				puts("Invalid password!");
			}

		}
	}
	else {
		puts("Not found!");
	}

}

struct node *search(char *key) {
	struct node* iter =NULL;
	if (table[(unsigned char)key[0]]) {
		for (iter = table[(unsigned char)key[0]]; iter != NULL; iter = iter->next) {
			if (!strcmp(iter->key, key)) {
				return iter;
			}
		}
	}
	else {
		return NULL;
	}
}

void add() {
	char buf[0x100];
	memset(buf, 0, 0x100);
	struct node* target = NULL;
	size_t size = 0;
	printf("Key:");
	read_input(buf, KEY_SIZE);
	target = search(buf);
	if (target) {
		hfree(target->data);
		printf("Size:");
		size = read_long();
		if (size >= 0x1000)
			size = 0x1000;
		target->data = (char*)hcalloc(1,size) ;
		printf("Data:");
		read_input(target->data, target->size);
	}
	else {
		target = (struct node*)hcalloc(1, sizeof(struct node));
		strncpy_s(target->key,buf,KEY_SIZE);
		printf("Size:");
		size = read_long();
		if (size >= 0x1000)
			size = 0x1000;
		target->size = size;
		target->data = (char*)hcalloc(1, size);
		printf("Data:");
		read_input(target->data, target->size);
		target->next = table[(unsigned char)buf[0]];
		table[(unsigned char)buf[0]] = target;
	}
	puts("Done!");
}

void view() {
	char buf[0x100];
	memset(buf, 0, 0x100);
	struct node* target = NULL;
	printf("Key:");
	read_input(buf, KEY_SIZE);
	target = search(buf);
	if (target) {
		_write(1, "Data:", 5);
		_write(1, target->data, target->size);
		_write(1, "\r\n", 2);
	}else {
		puts("Not found !");
	}
}

void remove() {
	char buf[0x100];
	memset(buf, 0, 0x100);
	struct node* target = NULL;
	printf("Key:");
	read_input(buf, KEY_SIZE);
	struct node* iter = NULL;
	struct node* prev = NULL;
	if (table[(unsigned char)buf[0]]) {
		for (iter = table[(unsigned char)buf[0]]; iter != NULL;iter = iter->next) {
			if (!strcmp(iter->key, buf)) {
				if (prev)
					prev->next = iter->next;
				else
					table[(unsigned char)buf[0]] = iter->next;
				hfree(iter->data);
				iter->data = NULL;
				hfree(iter);
				return;
			}
			prev = iter;
		}
	}
	else {
		puts("Not found !");
	}
}

int main(void) {
	unsigned long long choice;
	init_proc();
	while (1) {
		if (!is_login) {
			login_menu();
			choice = read_long();
			switch (choice) {
			case 1:
				login();
				break;
			case 2:
				_exit(0);
				break;
			default:
				puts("Invalid Choice");
				break;
			}
		}
		else {
			menu();
			choice = read_long();
			switch (choice) {
			case 1:
				add();
				break;
			case 2:
				view();
				break;
			case 3:
				remove();
				break;
			case 4:
				is_login = false;
				break;
			default:
				puts("Invalid Choice");
				break;
			}

		}
	}
}

