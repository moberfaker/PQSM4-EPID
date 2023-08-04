// 聊天程序客户端
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include"pch.h"//预编译头
#include<iostream>
#include<Winsock2.h>//socket头文件
#include<cstring>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "HiEasyX.h"
extern "C" {
#include <typeDefine.h>
#include "EPIDmanager.h"
#include <EPIDMember.h>
}
#include "uiDefine.h"
using namespace std;

#define SHOWCONSOLES 1

/* ========================================数据库======================================== */
// 消息窗口
Msgs message;
GP_MEMBER_CTX Mactx;

hiex::SysEdit edit;
bool INGroup = false;
volatile bool button_free = false;
clock_t start;
/* ========================================数据库======================================== */

void Deal_recv(size_t* Task, size_t* recv_len, char* buffer) {
	*Task = *(size_t*)(buffer);
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


//载入系统提供的socket动态链接库

#pragma comment(lib,"ws2_32.lib")   //socket库

const int BUFFER_SIZE = 400000;//缓冲区大小

DWORD WINAPI recvMsgThread(LPVOID IpParameter);

int main() {
	/* ================ 窗口与交互 ================ */

	hiex::Window wnd(600, 600, SHOWCONSOLES, L"电子车载功耗硬件 Client Serve");

	hiex::SysButton JOIN_btn(wnd.GetHandle(), BT_STA_X, BT_STA_Y, BT_WIT, BT_HIG, L"入群服务");
	hiex::SysEdit JOIN_name;
	JOIN_name.Create(wnd.GetHandle(), BT_STA_X - 10, BT_STA_Y - BT_GAP, 180, BT_HIG, L"产品序列号");
	JOIN_name.SetFont(24, 0, L"微软雅黑");
	JOIN_name.SetMaxTextLength(10);
	JOIN_name.SetTextColor(LIGHTGRAY);

	hiex::SysButton UPDATE_btn(wnd.GetHandle(), BT_STA_X, BT_STA_Y + BT_GAP, BT_WIT, BT_HIG, L"更新证书");
	hiex::SysButton REVOKE_btn(wnd.GetHandle(), BT_STA_X, BT_STA_Y + BT_GAP * 2, BT_WIT, BT_HIG, L"撤销秘钥");
	hiex::SysButton SIGN_btn(wnd.GetHandle(), 600 - BT_STA_X + 20 - 180, BT_STA_Y + BT_GAP * 2, BT_WIT, BT_HIG, L"服务请求(签名)");
	hiex::SysEdit SIGN_text;
	SIGN_text.Create(wnd.GetHandle(), 600 - BT_STA_X + 10 - 180, BT_STA_Y - BT_GAP, 180, BT_GAP * 3 - 15, L"签名消息");
	SIGN_text.SetFont(24, 0, L"微软雅黑");
	SIGN_text.SetMaxTextLength(20);
	SIGN_text.SetTextColor(LIGHTGRAY);

	edit.PreSetStyle({ true, false, true });
	edit.Create(wnd.GetHandle(), 20, 20, 580, 300, L"");
	edit.SetFont(20, 0, L"微软雅黑");
	edit.ReadOnly(true);

	/* ================ 窗口与交互 ================ */
	//1、初始化socket库
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//2、创建socket
	SOCKET cliSock = socket(AF_INET, SOCK_STREAM, 0);
	//3、打包地址
	//客户端
	SOCKADDR_IN cliAddr = { 0 };
	cliAddr.sin_family = AF_INET;
	cliAddr.sin_addr.s_addr = inet_addr("127.0.0.1");//IP地址
	cliAddr.sin_port = htons(12344);//端口号
	//服务端
	SOCKADDR_IN servAddr = { 0 };
	servAddr.sin_family = AF_INET;//AF_INET表示TCP/IP协议。
	servAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//服务端地址设置为本地回环地址
	servAddr.sin_port = htons(4221);//端口号设置为4221
	//尝试链接服务端
	while (connect(cliSock, (SOCKADDR*)&servAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		cout << "链接出现错误，错误代码" << WSAGetLastError() << endl;
		int ret = MessageBox(wnd.GetHandle(), L"链接出现错误！请尝试重新链接！", L"WRONING", MB_YESNO);
		if (ret == IDNO) {
			return 0;
		}
	}

	//创建接受消息线程
	CloseHandle(CreateThread(NULL, 0, recvMsgThread, (LPVOID)&cliSock, 0, 0));
	//主线程用于输入要发送的消息
	cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
	cout << "管理员服务：	1.申请入群  2.更新证书  3.撤销私钥" << endl;
	cout << "本地服务:      4.签名	    " << endl;
	cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;

	while (wnd.IsAlive())
	{
		Sleep(1);
		while (button_free);

		if (JOIN_btn.GetClickCount())
		{
			if (INGroup) {
				MessageBox(wnd.GetHandle(), L"已加入群组，不可重复加入！", L"WRONING", MB_OK);
			}
			else {
				button_free = true;
				char* name = WstringToChar(JOIN_name.GetText());
				start = clock() + 15;
				putMessage(edit.GetHandle(), L">>设置产品序列号:\t");
				putMessage(edit.GetHandle(), JOIN_name.GetText());
				putMessage(edit.GetHandle(), L"\r\n>>申请进入群组...\r\n");
				EPID_Member_Join1(&Mactx, (const char*)name, 0, &message);
				send(cliSock, (char*)message.message, message.message_len, 0);
			}
		}
		else if (UPDATE_btn.GetClickCount()) {
			if (INGroup) {
				button_free = true;
				putMessage(edit.GetHandle(), L">>发送证书更新请求...\r\n");
				start = clock();
				EPID_Member_update_cert_call(&message, &Mactx);
				send(cliSock, (char*)message.message, message.message_len, 0);
			}
			else {
				MessageBox(wnd.GetHandle(), L"证书更新失败:未加入任何群组！", L"WRONING", MB_OK);
			}
		}
		else if (REVOKE_btn.GetClickCount()) {
			if (INGroup) {
				button_free = true;
				putMessage(edit.GetHandle(), L">>发送成员撤销请求...\r\n");
				start = clock();
				EPID_Member_Exit_Group(&message, &Mactx);
				send(cliSock, (char*)message.message, message.message_len, 0);
				INGroup = false;
				putMessage(edit.GetHandle(), L">>成员撤销成功\r\n");
				putMessage(edit.GetHandle(), L">>耗时 ");
				putMessage(edit.GetHandle(), to_wstring((clock() - start) / 2));
				putMessage(edit.GetHandle(), L" ms\r\n\r\n");
				button_free = false;
			}
			else {
				MessageBox(wnd.GetHandle(), L"非法操作:未加入任何群组！", L"WRONING", MB_OK);
			}

		}
		else if (SIGN_btn.GetClickCount()) {
			if (INGroup) {
				if (Mactx.MemSize == 1) {
					MessageBox(wnd.GetHandle(), L"非法签名:当前群组仅1人，", L"WRONING", MB_OK);
					continue;
				}
				button_free = true;
				putMessage(edit.GetHandle(), L">>签名消息:\r\n\t");
				putMessage(edit.GetHandle(), SIGN_text.GetText());
				message.message = (uint8_t*)WstringToChar(SIGN_text.GetText());
				message.message_len = strlen((const char*)message.message);
				int ret, PreT, OnT;
				ret = EPID_Sign(&Mactx, &message, Mactx.MemSize, &PreT, &OnT);
				if (ret != -1) {
					putMessage(edit.GetHandle(), L"\r\n>>预处理时间:");
					putMessage(edit.GetHandle(), to_wstring(PreT / 2));
					putMessage(edit.GetHandle(), L"ms\t在线时间:");
					putMessage(edit.GetHandle(), to_wstring(OnT / 2));
					putMessage(edit.GetHandle(), L"ms\r\n");
					putMessage(edit.GetHandle(), L">>签名大小:");
					putMessage(edit.GetHandle(), to_wstring(int(ret / 1024)));
					putMessage(edit.GetHandle(), L" KB\r\n\r\n");

					putMessage(edit.GetHandle(), L">>提交签名消息与签名请求服务\r\n");
					int chec = send(cliSock, (char*)message.message, message.message_len, 0);
					printf("%d", chec);
				}
				else {
					button_free = false;
					MessageBox(wnd.GetHandle(), L"签名失败:请尝试更新数据", L"WRONING", MB_OK);
				}
			}
			else {
				MessageBox(wnd.GetHandle(), L"签名失败:未加入任何群组！", L"WRONING", MB_OK);
			}
		}
	}
	closesocket(cliSock);
	WSACleanup();
	return 0;
}

DWORD WINAPI recvMsgThread(LPVOID IpParameter)//接收消息的线程
{
	SOCKET cliSock = *(SOCKET*)IpParameter;//获取客户端的SOCKET参数

	while (1)
	{
		char buffer[BUFFER_SIZE] = { 0 };//字符缓冲区，用于接收和发送消息
		int nrecv = recv(cliSock, buffer, sizeof(buffer), 0);//nrecv是接收到的字节数
		if (nrecv > 0)//如果接收到的字符数大于0
		{
			//处理消息头
			size_t Task;
			size_t recv_len;
			Deal_recv(&Task, &recv_len, buffer);
			if (Task >= 0 && Task <= 10 && recv_len > 0) {
				//提取消息
				MsgsInit(&message, recv_len - 16);
				Msgsmemcpy(&message, buffer + 16, recv_len - 16);
				switch (Task)
				{
				case JOIN1:
					EPID_Member_Join2(&message, &Mactx);
					Sleep(15);
					send(cliSock, (char*)message.message, message.message_len, 0);
					putMessage(edit.GetHandle(), L">>成功发送申请请求\r\n");
					break;
				case JOIN2:
					EPID_Member_Join_finish(&message, &Mactx);
					cout << "======获取成员证书成功======" << endl;
					putMessage(edit.GetHandle(), L">>获取成员证书\r\n");
					putMessage(edit.GetHandle(), L">>耗时 ");
					putMessage(edit.GetHandle(), to_wstring((clock() - start) / 2));
					putMessage(edit.GetHandle(), L" ms\r\n\r\n");
					INGroup = true;
					button_free = false;
					break;
				case UPDATE:
					EPID_Member_update_cert(&message, &Mactx);
					cout << "======更新成员证书成功======" << endl;
					putMessage(edit.GetHandle(), L">>成员证书更新成功\r\n");
					putMessage(edit.GetHandle(), L">>耗时 ");
					putMessage(edit.GetHandle(), to_wstring((clock() - start) / 2));
					putMessage(edit.GetHandle(), L" ms\r\n\r\n");
					button_free = false;
				default:
					break;
				}

			}
			else {
				cout << buffer << endl;
				if (memcmp(buffer, "Verify Success!", 15) == 0) {
					putMessage(edit.GetHandle(), L">>官方验证通过\r\n\r\n");
					button_free = false;
				}
				else if (memcmp(buffer, "Verify Failed!", 14) == 0) {
					putMessage(edit.GetHandle(), L">>官方验证失败\r\n\r\n");
					button_free = false;
				}
				else if (memcmp(buffer, "Recevied Failed!", 16) == 0) {
					putMessage(edit.GetHandle(), L">>TCP数据丢失！\r\n\r\n");
					button_free = false;
				}
			}


		}
		else if (nrecv < 0)//如果接收到的字符数小于0就说明断开连接
		{
			cout << "与服务器断开连接" << endl;
			break;
		}
	}
	return 0;
}