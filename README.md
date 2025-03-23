编译和运行：

安装依赖项：
Bash

sudo apt-get install libmicrohttpd-dev openssl
编译代码：
Bash

gcc -o load_balancer load_balancer.c -lmicrohttpd -lssl -lcrypto
运行程序：
Bash

./load_balancer
访问 Web 界面：
在浏览器中访问 http://localhost:8088/config，并使用配置文件中设置的用户名和密码进行身份验证。
