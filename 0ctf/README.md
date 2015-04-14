---
layout: post
title: '0ctf 2015 Write-up'
date: 2015-04-02 16:28
comments: true
categories: 
---
freenote[400]
-

### 程式概述
+ freenote 為一個類似筆記功能的程式，這個程式分別有 List , New , Edit , Delete 四個主要的功能及 Exit 結束程式

![螢幕快照 2015-04-02 上午2.58.06.png](http://user-image.logdown.io/user/10979/blog/10598/post/259180/5QXQ5VlZTY2MiLRnZ2wm_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-04-02%20%E4%B8%8A%E5%8D%882.58.06.png)

+ 會用個 note struct 去紀錄每個筆記`是否為有效筆記`、`筆記大小`及`指向筆記內容的 pointer`

```c
struct note{
	int isValidNote; // 0 = not valid, 1 = valid
	int length;
	char content;
}
```

### 程式行為

+ 經過 ltrace 分析之後，可發現到一開始程式會先 malloc(0x1810) 用來存放這些 note struct，並以陣列的形式去儲存，其中的 index 即為筆記的編號，在最前方也紀錄共有多少筆記
	+ List 
		+ 會列出每個筆記的內容（也就是內容 pointer 所指向的地方），這裏使會列出筆記為`isValidNote == 1` 的內容
	+ New 
		+ 再輸入你要的大小之後，如果小於 128 byte 就會分配 128 byte 給你，但如果大於 128 byte 例如 252 byte ，那麼就會給你 128 + 128 byte 的大小，依此類推

	+ Edit
		+ 在輸入完要編輯的筆記及大小之後，程式會先判斷這個大小是否與之前的一樣，如果一樣則不會重新分配空間直接編輯內容，如過不一樣則會 realloc 夠你筆記大小的空間給他，不過這部分會先看原先分配空間的後面是否有足夠用的空間給他，如果夠用的話就不會改變起始位置
		
	+ Delete
		+ 輸入完要刪除的筆記後，會將 note[i] 中的 `isValidNote` 改成 0，在 `free(note[i]->content)`，並將`筆記總數 - 1 `

### 漏洞

+ Double free
	+ 在 Delete 時，並不會將筆記從 `note[i]` 中移除，只是將 `isValidNote = 0` ，而 free 是根據 `note[i]` 去決定要 free 哪邊，並沒有先去檢查 `note[i]->content` 是否已經被 free 掉，一旦輸入同樣的 `i` 就會造成 double free 的漏洞

+ Memory leak
	+ 因在輸入筆記後，程式並沒有在使用者輸入的內容最後方補上 `\0` ，因此在 `free(note[i])` 之後，該空間會被加入 `free chunk` 並有 `fd` 及 `bk` 欄位，會指向 heap，當 `note[i-1]` 使用 `edit` 加大空間後，可巧妙的接續在 `fd` 或 `bk` 之前，而在使用 List 之後便可 leak 出 heap 中上次 free 掉空間的位置，這些位置的 offset 都是固定的，因此可以算出 `heap base`

### 漏洞利用及思路
+ 為了要利用 double free 這個漏洞去改其他位置的值，必須先觸發 `unlink()` 不過要觸發 `unlink()` 必須滿足下列三個條件其中一種：
	+ 如果下一塊是 top chunk，且上一塊是 free chunk
		+ 最後合併到 top chunk
	+ 如果下一塊不是 top chunk
		+ 上一塊是 free chunk
		+ 下一塊是 free chunk
+ 然而紀錄上一塊是不是 free chunk 的及大小資訊（ free 是利用這些資訊去尋找上一塊 chunk 位置），會記錄在目前這塊 chunk 的 meta 中，也就是說要確定該快 chunk 是否為已經 free 的狀態是由下一塊的 chunk 所決定的，所以如果使用`下一塊是 free chunk ` 這個條件必須改到下下一塊 chunk 的 meta data 或是利用特殊的方法欺騙 free() 下下一塊的位置，也就是必須動到三塊的 chunk 的 meta data，所以這部分稍微會比較麻煩一點點，故決定採用`上一塊是 free chunk` 這個條件來達成。
+ leak heap
	+ 建立四塊左右的 note，`delete 0,2 塊`，再利用前面所述的方法，算出 heap 位置
+ 構建 fake chunk
	+ 先 new 三塊 note 之後，delete 第二塊的，再利用 edit 加大第一塊的空間，使得可以蓋過第二塊的 `meta data
`起初大概的改法如下
		
    ![螢幕快照 2015-04-02 下午4.41.08.png](http://user-image.logdown.io/user/10979/blog/10598/post/259180/we2Q2qXkSz66x6wq1HAR_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-04-02%20%E4%B8%8B%E5%8D%884.41.08.png)
    
    
	+ 但使用後缺發現會一直出現 `double linked corruption`
  	
    ![螢幕快照 2015-04-02 下午2.48.29.png](http://user-image.logdown.io/user/10979/blog/10598/post/259180/Fh8lSVzFQK6IliK8tFCC_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-04-02%20%E4%B8%8B%E5%8D%882.48.29.png)
    
	+ 仔細查看後才發現到原來有 `FD->bk != P || BK->fd != P` 這項保護的機制在，不能直接改，因此必須找到滿足 `P->fd->bk == P` 及 `P->bk->fd == P` 的 pointer，才有機會利用
	+ 過了很久才想到在 note[i] 中都有指向 content 的 pointer 只要稍作修改就可偽造不同 size 的 chunk 讓 free 以為 `note[i]->content` 所指的位置為 chunk 的 head，這一步應該就是最關鍵的地方，也是讓我卡比較多時間的地方，其最後改法如下圖所示（黃框為 fake chunk ）：
  
		![螢幕快照 2015-04-02 下午4.42.09.png](http://user-image.logdown.io/user/10979/blog/10598/post/259180/kuc4IGSMQOCjyJLXj3Dg_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-04-02%20%E4%B8%8B%E5%8D%884.42.09.png)

	+ 在 `delete note[1]` 也就是 free(note[1]->content) 之後便可成功改到 `note[0]` 讓 
		+ `note[0]->content = &(note[0]->content)-0x10` 亦及 FD->bk = BK
		+ `note[0]->content = &(note[0]->content)-0x18` 亦及 BK->fd = FD
	+ 因此 note[0]->content 位置就變成了 `&(note[0]->content)-0x18` ，這樣就可以利用 edit 任意更改 `note[i]` 的內容
+ 更改 note[i]
	+ 我這邊稍作了修改將 note 變成六塊
		+ 第 0-1 塊用來 leak heap 位置用
		+ 第 2-3 塊用來更改 `note[i]` 的內容
		+ 因此只要再次用 edit 更改同樣大小的內容，便可改掉整個 note，這部分定要跟之前說 new 的大小相同，否則會重新 realloc 會失敗，示意圖大概如下
    
        ![螢幕快照 2015-04-02 下午4.44.25.png](http://user-image.logdown.io/user/10979/blog/10598/post/259180/bWJnOl53QiqjrexCEtIl_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-04-02%20%E4%B8%8B%E5%8D%884.44.25.png)
    
    
		+ 第 4-5 塊最後會用來改 atoi 的 got 
			+ 事實上可以不用這麼多塊，但只是怕亂掉所以每塊都分開
	+ 再來將 `note[i]` 部分內容改成 `free_got` 及 `atoi_got` 位置
  	
    ![螢幕快照 2015-04-02 下午4.45.07.png](http://user-image.logdown.io/user/10979/blog/10598/post/259180/FmHdZ9nQQenPI5qLGdNw_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-04-02%20%E4%B8%8B%E5%8D%884.45.07.png)
    
+ leak libc 位置
	+ 使用 list 後，可利用 got 來算出 libc 的位置
+ 改 got
	+ 再用 edit 更改 `note[5]` 後，便可將 atoi 的 got 內容改為 `system`
+ 跳轉到 system
	+ 直接輸入 `/bin/sh` 就會去執行 `system('/bin/sh')`，這樣就拿到 shell 了
  
+ exploit
[exploit](https://github.com/scwuaptx/CTF/blob/master/0ctf/freenote.py)

### 心得
+ 這次 0ctf 題目算是不會很難，只是不知道為什麼第二天就體力不支了，整整兩天只解了 freenote 這題，不過這次題目出的我個人覺得還算不錯，也挺好玩的，只是實力與經驗還需再加強，也要再多多練一下其他領域的題目，不然每次解 pwn 之外的題目都幾乎不會解，就連最簡單的 SQL injection 都會有點問題，不過我覺得 freenote 這題是很棒的一題，可以拿來練習 heap exploition 的部分，未來有時間再來整理有關 heap exploition 的資料。