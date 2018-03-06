# smcDemo

参照hctf2017 re3_are_u_ok来自己实现了一个smcDemo.



##使用流程

###生成未加密的smcDemo

$ gcc -z execstack sm4.c smcDemo.c -o smcDemo

注意, 这样生成的smcDemo并不能正确执行, 因为还并没有将里面的两个重要函数进行加密, 但是在程序执行时会自动解密这两个函数

###将函数进行sm4加密处理

$ genFlag

###

这里提供了一个已经基本修改好的smcDemo-final.
具体实现原理, 可以参看源码. 或者作者会在Blog中分享一篇文章(Blog地址:L0phTg.github.io)
