背景：
	attestation 主要分为两部分，get-attestation 和verify-attestation，get-attestation 有两种方案实现，
	一种是在内核态调用vmmcall 获取attestation report，另外一种是在用户态调用vmmcal，内核态调用vmmcall 需要配合驱动支持，
	由于kata 容器安全性做了隔离，正常启动容器访问不了/proc/self/pagemap 文件，导致原有attestation 代码不能将虚拟机地址转换成物理地址，导致
获取attestation report失败，无法使用用户态vmmcall，kata 使用内核驱动csv-guest.c 配合ioctl_get_attestation 获取attestation report文件
	同时，提供attestation 的静态和动态两种编译方式，静态编译生成的可执行文件不依赖库，可单独执行，便于测试使用，为默认编译项，
动态编译生成的可执行文件依赖库，程序执行时需调用库，但编译速度快，生成的文件体积小，这里提供SDK和两种编译方式供用户进行二次开发


方案介绍：
	1、用户态方案：
		用户态调用vmmcall 直接获取attestation report文件，不需要驱动支持
	2、内核方案：
		在内核中添加一个csv-guest驱动，get-attestation 通过ioctl 对驱动进行操作，将用户态
		分配的虚拟地址传入到内核，拷贝虚拟地址中的user data mnonce 内存数据到内核分配的内存，
		在内核中调用hypercall 获取attestation 数据到内核内存，然后将attestation report数据从内核态拷贝到用户态


编译介绍：
	1、静态编译：
		$ gcc -c csv_sdk/*.c
		$ ar -r libcsv.a *.o
		$ gcc -o get-attestation vmmcall_get_attestation.c -L. libcsv.a
		将csv_sdk 目录下的.c 文件编译为.o 文件，再将这些.o 文件组合为.a 静态库文件，最后链接该静态库文件编译生成可执行程序
	2、动态编译：
		$ gcc -c -fpic csv_sdk/*.c
		$ gcc -o libcsv.so -shared *.o
		$ gcc -o get-attestation vmmcall_get_attestation.c -L. libcsv.so
		将csv_sdk 目录下的.c 文件编译为.o 文件，再将这些.o 文件编译为.so 动态库文件，最后链接该动态库文件编译生成可执行程序


代码介绍
	.
	├── calc_vm_digest.c
	├── csv_status.h
	├── csv-guest.c                             // csv-guest 驱动程序，必须静态编译到kata内核中
	├── csv_sdk                                 // 封装好的SDK，可供用户进行二次开发
	│   ├── csv_sdk.h
	│   ├── csv_status.c
	│   ├── ioctl_get_attestation_report.c
	│   ├── ioctl_get_sealing_key.c
	│   └── vmmcall_get_sealing_key.c
	├── ioctl_get_attestation.c                 // 通过驱动配合获取attestation report
	├── ioctl_get_key.c                         // 通过驱动配合获取sealing key
	├── Makefile
	├── readme.txt
	├── verify_attestation.c                    // 验证 report.cert 程序
	├── vmmcall_get_attestation.c               // 用户态获取attestation report
	└── vmmcall_get_key.c                       // 用户态获取sealing key


SDK使用介绍
	主要是调用csv_sdk.h中的五个函数接口
	1、int vmmcall_get_attestation_report(unsigned char* report_buf, unsigned int buf_len);
		应用程序分配长度为buf_len个字节的内存report_buf，调用该函数使用vmmcall发送ATTESTATION命令，attestation report保存在report_buf

	2、int ioctl_get_attestation_report(unsigned char* report_buf, unsigned int buf_len);
		应用程序分配长度为buf_len个字节的内存report_buf，调用该函数使用ioctl通知内核发送ATTESTATION命令，attestation report保存在report_buf

	3、int verify_attestation_report(unsigned char* report_buf, unsigned int buf_len, int verify_chain);
		应用程序分配长度为buf_len的内存report_buf，attestation report保存在report_buf，调用该函数验证attestation report，当verify_chain=1 时会验证证书链，verify_chain=0 时不会验证证书链

	4、int vmmcall_get_sealing_key(unsigned char* key_buf, unsigned int buf_len);
		应用程序分配长度为buf_len个字节的内存key_buf，调用该函数使用vmmcall发送ATTESTATION命令，sealing key保存在key_buf

	5、int ioctl_get_sealing_key(unsigned char* key_buf, unsigned int buf_len);
		应用程序分配长度为buf_len个字节的内存key_buf，调用该函数使用ioctl通知内核发送ATTESTATION命令，sealing key保存在key_buf


kata 验证流程：
	1、编译好带csv-guest驱动的内核，替换原有kata内核
	2、启动容器，命令如下
	   sudo docker run --name csv -t -i -v /dev/csv-guest:/dev/csv-guest ubuntu bash，需要使用-v /dev/csv-guest:/dev/csv-guest
	   将驱动/dev/csv-guest 节点挂载，否则节点不会出现
	3、将编译好的ioctl_get_attestation 拷贝到容器中，执行ioctl_get_attestation获取report.cert 文件，拷贝report.cert 文件到主机上通过verify-attestation 验证
kata 获取sealing key流程：
	将编译好的ioctl_get_key 拷贝到容器中，执行ioctl_get_key获取sealing key


虚拟机验证流程：
	将编译好的get-attestation 拷贝到虚拟机中，执行get-attestation获取report.cert 文件，拷贝report.cert  文件到主机上通过verify-attestation 验证
虚拟机获取sealing key流程：
	编译好的get_key 拷贝到虚拟机中，执行get_key获取sealing key



