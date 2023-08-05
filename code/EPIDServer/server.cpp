#include"pch.h"//预编译头
#include<iostream>
#include<Winsock2.h>//socket头文件
#include<cstring>
#include <stdio.h>
#include <assert.h>
#include <graphics.h>
#include "HiEasyX.h"
extern "C" {
#include <typeDefine.h>
#include <EPIDmanager.h>
#include <EPIDMember.h>
}
using namespace std;

#define SHOWCONSOLES 1


//载入系统提供的socket动态链接库
#pragma comment(lib,"ws2_32.lib")   //socket库

//==============================全局变量区===================================
const int BUFFER_SIZE = 400000;//缓冲区大小
int RECV_TIMEOUT = 20;//接收消息超时
int SEND_TIMEOUT = 20;//发送消息超时
const int WAIT_TIME = 20;//每个客户端等待事件的时间，单位毫秒
const int MAX_LINK_NUM = 10;//服务端最大链接数
SOCKET cliSock[MAX_LINK_NUM];//客户端套接字 0号为服务端
SOCKADDR_IN cliAddr[MAX_LINK_NUM];//客户端地址
WSAEVENT cliEvent[MAX_LINK_NUM];//客户端事件 0号为服务端,它用于让程序的一部分等待来自另一部分的信号。例如，当数据从套接字变为可用时，winsock 库会将事件设置为信号状态
int total = 0;//当前已经链接的客服端服务数
int total_serve = 0;	//当前通过的签名

//==============================函数声明===================================
DWORD WINAPI servEventThread(LPVOID IpParameter);//服务器端处理线程
void Deal_recv(size_t* Task, size_t* recv_len, char* buffer) {
	*Task = *(buffer);
	*recv_len = *(size_t*)(buffer + 8);
}

char* WstringToChar(const std::wstring& ws) {
	const wchar_t* wp = ws.c_str();
	int len = WideCharToMultiByte(CP_ACP, 0, wp, wcslen(wp), NULL, 0, NULL, NULL);
	char* m_char = new char[len + 1];
	WideCharToMultiByte(CP_ACP, 0, wp, wcslen(wp), m_char, len, NULL, NULL);
	m_char[len] = '\0';
	return m_char;
}

void putMessage(HWND hParent, std::wstring wstr) {
	// 在光标位置后插入文本
	SendMessage(hParent, EM_SETSEL, (WPARAM)-1, (LPARAM)0);
	SendMessage(hParent, EM_REPLACESEL, true, (LPARAM)wstr.c_str());
}

wchar_t* char2wchar(const char* cchar)
{
	wchar_t* m_wchar;
	int len = MultiByteToWideChar(CP_ACP, 0, cchar, strlen(cchar), NULL, 0);
	m_wchar = new wchar_t[len + 1];
	MultiByteToWideChar(CP_ACP, 0, cchar, strlen(cchar), m_wchar, len);
	m_wchar[len] = '\0';
	return m_wchar;
}

uint8_t* get_sigtext(uint8_t* text, size_t text_len) {
	uint8_t* temp = (uint8_t*)malloc(text_len);
	for (size_t i = 0; i <= text_len; i++) {
		if (text[i] == '|') {
			temp[i] = '\t';
		}
		else {
			temp[i] = text[i];
		}
	}
	return temp;
}

/* ========================================数据库======================================== */
// 群ID池
int IDPool = 0;
int T = sizeof(GP_MANAGER_CTX);
GP_MANAGER_CTX Gpctx[1];
// 消息窗口
Msgs message;

hiex::SysEdit edit;
/* ========================================数据库======================================== */


int main()
{
	/* ================ 窗口与交互 ================ */
	hiex::Window wnd(400 + 80, 600, SHOWCONSOLES, L"充电桩服务请求列表");

	edit.PreSetStyle({ true, false, true });
	edit.Create(wnd.GetHandle(), 20, 20 + 20, 360 + 80, 560 - 20, L"");
	edit.SetFont(24, 2, L"微软雅黑");
	putMessage(edit.GetHandle(), L" 请求序列\t\t当前电量\t\t车辆型号\t\t充电时长\r\n");
	putMessage(edit.GetHandle(), L"==============================================\r\n");
	edit.SetFont(18, 0, L"微软雅黑");
	edit.ReadOnly(true);
	/* ================ 窗口与交互 ================ */

	// 群0初始化
	EPID_Group_Init(&Gpctx[0], EPID_L1, &IDPool);

	//1、初始化socket库
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//2、创建socket
	SOCKET servSock = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN servAddr;
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	//端口号设置为4221
	servAddr.sin_port = htons(4221);
	//3、绑定服务端
	bind(servSock, (SOCKADDR*)&servAddr, sizeof(servAddr));
	WSAEVENT servEvent = WSACreateEvent();
	WSAEventSelect(servSock, servEvent, FD_ALL_EVENTS);
	cliSock[0] = servSock;
	cliEvent[0] = servEvent;
	//5、开启监听
	//监听队列长度为10
	listen(servSock, 10);
	//6、创建接受链接的线程
	CloseHandle(CreateThread(NULL, 0, servEventThread, (LPVOID)&servSock, 0, 0));
	cout << "\n\n================群服务端开启================" << endl;
	cout << "服务：	1.申请入群  2.更新证书  3.撤销私钥" << endl;
	while (1)
	{
		char contentBuf[BUFFER_SIZE / 400] = { 0 };
		char sendBuf[BUFFER_SIZE / 400] = { 0 };
		cin.getline(contentBuf, sizeof(contentBuf));
		sprintf(sendBuf, "[群管理员]%s", contentBuf);
		//发送管理员消息
		for (int j = 1; j <= total; j++)
			send(cliSock[j], sendBuf, sizeof(sendBuf), 0);
	}
	WSACleanup();
	return 0;
}


DWORD WINAPI servEventThread(LPVOID IpParameter) //服务器端线程
{
	//该线程负责处理服务端和各个客户端发生的事件
	//将传入的参数初始化
	SOCKET servSock = *(SOCKET*)IpParameter;//LPVOID为空指针类型，需要先转成SOCKET类型再引用，即可使用传入的SOCKET
	while (1) //不停执行
	{
		for (int i = 0; i < total + 1; i++)//i代表现在正在监听事件的终端
		{
			//若有一个客户端链接，total==1，循环两次，包含客户端和服务端
			//对每一个终端（客户端和服务端），查看是否发生事件，等待WAIT_TIME毫秒
			int index = WSAWaitForMultipleEvents(1, &cliEvent[i], false, WAIT_TIME, 0);

			index -= WSA_WAIT_EVENT_0;//此时index为发生事件的终端下标

			if (index == WSA_WAIT_TIMEOUT || index == WSA_WAIT_FAILED)
			{
				continue;//如果出错或者超时，即跳过此终端
			}

			else if (index == 0)
			{
				WSANETWORKEVENTS networkEvents;
				WSAEnumNetworkEvents(cliSock[i], cliEvent[i], &networkEvents);//查看是什么事件

				//事件选择
				if (networkEvents.lNetworkEvents & FD_ACCEPT)//若产生accept事件（此处与位掩码相与）
				{
					if (networkEvents.iErrorCode[FD_ACCEPT_BIT] != 0)
					{
						cout << "连接时产生错误，错误代码" << networkEvents.iErrorCode[FD_ACCEPT_BIT] << endl;
						continue;
					}
					//接受链接
					if (total + 1 < MAX_LINK_NUM)//若增加一个客户端仍然小于最大连接数，则接受该链接
					{
						//total为已连接客户端数量
						int nextIndex = total + 1;//分配给新客户端的下标
						int addrLen = sizeof(SOCKADDR);
						SOCKET newSock = accept(servSock, (SOCKADDR*)&cliAddr[nextIndex], &addrLen);
						if (newSock != INVALID_SOCKET)
						{
							//设置发送和接收时限
							/*setsockopt(newSock, SOL_SOCKET, SO_SNDTIMEO, (const char*) & SEND_TIMEOUT, sizeof(SEND_TIMEOUT));
							setsockopt(newSock, SOL_SOCKET, SO_SNDTIMEO, (const char*) &RECV_TIMEOUT, sizeof(RECV_TIMEOUT));*/
							//给新客户端分配socket
							cliSock[nextIndex] = newSock;
							//新客户端的地址已经存在cliAddr[nextIndex]中了
							//为新客户端绑定事件对象,同时设置监听，close，read，write
							WSAEVENT newEvent = WSACreateEvent();
							WSAEventSelect(cliSock[nextIndex], newEvent, FD_CLOSE | FD_READ | FD_WRITE);
							cliEvent[nextIndex] = newEvent;
							total++;//客户端连接数增加
							cout << "#" << nextIndex << "成员（IP：" << inet_ntoa(cliAddr[nextIndex].sin_addr) << ")进入群" << endl;

						}
					}

				}
				else if (networkEvents.lNetworkEvents & FD_CLOSE)//客户端被关闭，即断开连接
				{

					//i表示已关闭的客户端下标
					total--;
					cout << "#" << i << "成员（IP：" << inet_ntoa(cliAddr[i].sin_addr) << ")退出服务器" << endl;
					//释放这个客户端的资源
					closesocket(cliSock[i]);
					WSACloseEvent(cliEvent[i]);

					//数组调整,用顺序表删除元素
					for (int j = i; j < total; j++)
					{
						cliSock[j] = cliSock[j + 1];
						cliEvent[j] = cliEvent[j + 1];
						cliAddr[j] = cliAddr[j + 1];
					}


				}
				else if (networkEvents.lNetworkEvents & FD_READ)//接收到消息
				{

					char buffer[BUFFER_SIZE] = { 0 };//字符缓冲区，用于接收消息
					for (int j = 1; j <= total; j++)
					{
						int recvBufferSize;
						int len = sizeof(recvBufferSize);
						getsockopt(cliSock[j], SOL_SOCKET, SO_RCVBUF, (char*)&recvBufferSize, &len);
						int totalBytesReceived = 0;
						int bytesReceived;

						int nrecv = recv(cliSock[j], buffer, sizeof(buffer), 0);//nrecv是接收到的字节数
						if (nrecv > 0)//如果接收到的字符数大于0
						{
							//处理消息头
							size_t Task;
							size_t recv_len;
							Deal_recv(&Task, &recv_len, buffer);
							if (Task >= 0 && Task <= 10 && recv_len > 0) {
								MsgsInit(&message, recv_len - 16);
								Msgsmemcpy(&message, buffer + 16, recv_len - 16);
								totalBytesReceived = nrecv;
								bool check = true;
								if (totalBytesReceived < recv_len) {
									send(cliSock[j], "Recevied Failed!", 16, 0);
									check = false;
								}
								//while (totalBytesReceived < recv_len) {
								//	bytesReceived = recv(cliSock[j], buffer + totalBytesReceived, recvBufferSize, 0);
								//	totalBytesReceived += bytesReceived;
								//	int errorif = getsockopt(cliSock[j], SOL_SOCKET, SO_RCVBUF, (char*)&recvBufferSize, &len);
								//	if (bytesReceived == 0xffffffff) {
								//		send(cliSock[j], "Recevied Failed!", 15, 0);
								//		check = false;
								//		break;
								//	}
								//	// 在这里处理接收到的数据
								//}
								if (check == false)
									break;
							}
							else {
								cout << "[#" << j << "]" << buffer << endl;
							}

							if (Task >= 0 && Task <= 10 && recv_len > 0)
								switch (Task)
								{
								case JOIN1:
									cout << "[#" << j << "]" << "请求入群..." << endl;
									EPID_Group_Join1(&message, Gpctx);
									sprintf(buffer, "[群管理员]发送（群公钥、挑战）\n");
									send(cliSock[j], buffer, sizeof(buffer), 0);
									send(cliSock[j], (const char*)message.message, message.message_len, 0);
									break;
								case JOIN2:
									cout << "[#" << j << "]" << "回应挑战..." << endl;
									EPID_Group_Join2(&message, Gpctx);
									sprintf(buffer, "[群管理员]颁布证书\n");
									send(cliSock[j], buffer, sizeof(buffer), 0);
									send(cliSock[j], (const char*)message.message, message.message_len, 0);
									break;
								case UPDATE:
									cout << "[#" << j << "]" << "请求更新证书..." << endl;
									EPID_Manager_updaet_cert(&message, Gpctx);
									send(cliSock[j], (const char*)message.message, message.message_len, 0);
									break;
								case REVOKEKEY:
									cout << "[#" << j << "]" << "退出群组..." << endl;
									EPID_Manager_Exit_Group(&message, Gpctx);
									break;
								case SIGN:
									cout << "[#" << j << "]" << "请求签名验证..." << endl;
									int ret;
									uint8_t* text;
									text = NULL;
									printf("%d", nrecv);
									ret = EPID_Verify(&text, &message, Gpctx->MemSize, Gpctx->ComList.X);
									printf("签名消息： %s\n", text);	//此处为固定窗口列表输出
									text = get_sigtext(text, strlen((const char*)text));
									if (ret == 0) {
										send(cliSock[j], "Verify Success!", 16, 0);
										total_serve++;
										putMessage(edit.GetHandle(), L"  【");
										putMessage(edit.GetHandle(), to_wstring(total_serve));
										putMessage(edit.GetHandle(), L"】\t\t");

										putMessage(edit.GetHandle(), char2wchar((const char*)text));
										putMessage(edit.GetHandle(), L"\r\n");
										putMessage(edit.GetHandle(), L"----------------------------------------------------------------------------------\r\n");
									}
									else
										send(cliSock[j], "Verify Failed!", 15, 0);
									break;
								default:
									sprintf(buffer, "[#%d]%s", j, buffer);
									cout << buffer << endl;
									break;
								}
						}

					}
				}
			}
		}


	}
	return 0;
}