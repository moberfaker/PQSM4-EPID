// �������ͻ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include"pch.h"//Ԥ����ͷ
#include<iostream>
#include<Winsock2.h>//socketͷ�ļ�
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

/* ========================================���ݿ�======================================== */
// ��Ϣ����
Msgs message;
GP_MEMBER_CTX Mactx;

hiex::SysEdit edit;
bool INGroup = false;
volatile bool button_free = false;
clock_t start;
/* ========================================���ݿ�======================================== */

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
	// �ڹ��λ�ú�����ı�
	SendMessage(hParent, EM_SETSEL, (WPARAM)-1, (LPARAM)0);
	SendMessage(hParent, EM_REPLACESEL, true, (LPARAM)wstr.c_str());
}


//����ϵͳ�ṩ��socket��̬���ӿ�

#pragma comment(lib,"ws2_32.lib")   //socket��

const int BUFFER_SIZE = 400000;//��������С

DWORD WINAPI recvMsgThread(LPVOID IpParameter);

int main() {
	/* ================ �����뽻�� ================ */

	hiex::Window wnd(600, 600, SHOWCONSOLES, L"���ӳ��ع���Ӳ�� Client Serve");

	hiex::SysButton JOIN_btn(wnd.GetHandle(), BT_STA_X, BT_STA_Y, BT_WIT, BT_HIG, L"��Ⱥ����");
	hiex::SysEdit JOIN_name;
	JOIN_name.Create(wnd.GetHandle(), BT_STA_X - 10, BT_STA_Y - BT_GAP, 180, BT_HIG, L"��Ʒ���к�");
	JOIN_name.SetFont(24, 0, L"΢���ź�");
	JOIN_name.SetMaxTextLength(10);
	JOIN_name.SetTextColor(LIGHTGRAY);

	hiex::SysButton UPDATE_btn(wnd.GetHandle(), BT_STA_X, BT_STA_Y + BT_GAP, BT_WIT, BT_HIG, L"����֤��");
	hiex::SysButton REVOKE_btn(wnd.GetHandle(), BT_STA_X, BT_STA_Y + BT_GAP * 2, BT_WIT, BT_HIG, L"������Կ");
	hiex::SysButton SIGN_btn(wnd.GetHandle(), 600 - BT_STA_X + 20 - 180, BT_STA_Y + BT_GAP * 2, BT_WIT, BT_HIG, L"��������(ǩ��)");
	hiex::SysEdit SIGN_text;
	SIGN_text.Create(wnd.GetHandle(), 600 - BT_STA_X + 10 - 180, BT_STA_Y - BT_GAP, 180, BT_GAP * 3 - 15, L"ǩ����Ϣ");
	SIGN_text.SetFont(24, 0, L"΢���ź�");
	SIGN_text.SetMaxTextLength(20);
	SIGN_text.SetTextColor(LIGHTGRAY);

	edit.PreSetStyle({ true, false, true });
	edit.Create(wnd.GetHandle(), 20, 20, 580, 300, L"");
	edit.SetFont(20, 0, L"΢���ź�");
	edit.ReadOnly(true);

	/* ================ �����뽻�� ================ */
	//1����ʼ��socket��
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//2������socket
	SOCKET cliSock = socket(AF_INET, SOCK_STREAM, 0);
	//3�������ַ
	//�ͻ���
	SOCKADDR_IN cliAddr = { 0 };
	cliAddr.sin_family = AF_INET;
	cliAddr.sin_addr.s_addr = inet_addr("127.0.0.1");//IP��ַ
	cliAddr.sin_port = htons(12344);//�˿ں�
	//�����
	SOCKADDR_IN servAddr = { 0 };
	servAddr.sin_family = AF_INET;//AF_INET��ʾTCP/IPЭ�顣
	servAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//����˵�ַ����Ϊ���ػػ���ַ
	servAddr.sin_port = htons(4221);//�˿ں�����Ϊ4221
	//�������ӷ����
	while (connect(cliSock, (SOCKADDR*)&servAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		cout << "���ӳ��ִ��󣬴������" << WSAGetLastError() << endl;
		int ret = MessageBox(wnd.GetHandle(), L"���ӳ��ִ����볢���������ӣ�", L"WRONING", MB_YESNO);
		if (ret == IDNO) {
			return 0;
		}
	}

	//����������Ϣ�߳�
	CloseHandle(CreateThread(NULL, 0, recvMsgThread, (LPVOID)&cliSock, 0, 0));
	//���߳���������Ҫ���͵���Ϣ
	cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
	cout << "����Ա����	1.������Ⱥ  2.����֤��  3.����˽Կ" << endl;
	cout << "���ط���:      4.ǩ��	    " << endl;
	cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;

	while (wnd.IsAlive())
	{
		Sleep(1);
		while (button_free);

		if (JOIN_btn.GetClickCount())
		{
			if (INGroup) {
				MessageBox(wnd.GetHandle(), L"�Ѽ���Ⱥ�飬�����ظ����룡", L"WRONING", MB_OK);
			}
			else {
				button_free = true;
				char* name = WstringToChar(JOIN_name.GetText());
				start = clock() + 15;
				putMessage(edit.GetHandle(), L">>���ò�Ʒ���к�:\t");
				putMessage(edit.GetHandle(), JOIN_name.GetText());
				putMessage(edit.GetHandle(), L"\r\n>>�������Ⱥ��...\r\n");
				EPID_Member_Join1(&Mactx, (const char*)name, 0, &message);
				send(cliSock, (char*)message.message, message.message_len, 0);
			}
		}
		else if (UPDATE_btn.GetClickCount()) {
			if (INGroup) {
				button_free = true;
				putMessage(edit.GetHandle(), L">>����֤���������...\r\n");
				start = clock();
				EPID_Member_update_cert_call(&message, &Mactx);
				send(cliSock, (char*)message.message, message.message_len, 0);
			}
			else {
				MessageBox(wnd.GetHandle(), L"֤�����ʧ��:δ�����κ�Ⱥ�飡", L"WRONING", MB_OK);
			}
		}
		else if (REVOKE_btn.GetClickCount()) {
			if (INGroup) {
				button_free = true;
				putMessage(edit.GetHandle(), L">>���ͳ�Ա��������...\r\n");
				start = clock();
				EPID_Member_Exit_Group(&message, &Mactx);
				send(cliSock, (char*)message.message, message.message_len, 0);
				INGroup = false;
				putMessage(edit.GetHandle(), L">>��Ա�����ɹ�\r\n");
				putMessage(edit.GetHandle(), L">>��ʱ ");
				putMessage(edit.GetHandle(), to_wstring((clock() - start) / 2));
				putMessage(edit.GetHandle(), L" ms\r\n\r\n");
				button_free = false;
			}
			else {
				MessageBox(wnd.GetHandle(), L"�Ƿ�����:δ�����κ�Ⱥ�飡", L"WRONING", MB_OK);
			}

		}
		else if (SIGN_btn.GetClickCount()) {
			if (INGroup) {
				if (Mactx.MemSize == 1) {
					MessageBox(wnd.GetHandle(), L"�Ƿ�ǩ��:��ǰȺ���1�ˣ�", L"WRONING", MB_OK);
					continue;
				}
				button_free = true;
				putMessage(edit.GetHandle(), L">>ǩ����Ϣ:\r\n\t");
				putMessage(edit.GetHandle(), SIGN_text.GetText());
				message.message = (uint8_t*)WstringToChar(SIGN_text.GetText());
				message.message_len = strlen((const char*)message.message);
				int ret, PreT, OnT;
				ret = EPID_Sign(&Mactx, &message, Mactx.MemSize, &PreT, &OnT);
				if (ret != -1) {
					putMessage(edit.GetHandle(), L"\r\n>>Ԥ����ʱ��:");
					putMessage(edit.GetHandle(), to_wstring(PreT / 2));
					putMessage(edit.GetHandle(), L"ms\t����ʱ��:");
					putMessage(edit.GetHandle(), to_wstring(OnT / 2));
					putMessage(edit.GetHandle(), L"ms\r\n");
					putMessage(edit.GetHandle(), L">>ǩ����С:");
					putMessage(edit.GetHandle(), to_wstring(int(ret / 1024)));
					putMessage(edit.GetHandle(), L" KB\r\n\r\n");

					putMessage(edit.GetHandle(), L">>�ύǩ����Ϣ��ǩ���������\r\n");
					int chec = send(cliSock, (char*)message.message, message.message_len, 0);
					printf("%d", chec);
				}
				else {
					button_free = false;
					MessageBox(wnd.GetHandle(), L"ǩ��ʧ��:�볢�Ը�������", L"WRONING", MB_OK);
				}
			}
			else {
				MessageBox(wnd.GetHandle(), L"ǩ��ʧ��:δ�����κ�Ⱥ�飡", L"WRONING", MB_OK);
			}
		}
	}
	closesocket(cliSock);
	WSACleanup();
	return 0;
}

DWORD WINAPI recvMsgThread(LPVOID IpParameter)//������Ϣ���߳�
{
	SOCKET cliSock = *(SOCKET*)IpParameter;//��ȡ�ͻ��˵�SOCKET����

	while (1)
	{
		char buffer[BUFFER_SIZE] = { 0 };//�ַ������������ڽ��պͷ�����Ϣ
		int nrecv = recv(cliSock, buffer, sizeof(buffer), 0);//nrecv�ǽ��յ����ֽ���
		if (nrecv > 0)//������յ����ַ�������0
		{
			//������Ϣͷ
			size_t Task;
			size_t recv_len;
			Deal_recv(&Task, &recv_len, buffer);
			if (Task >= 0 && Task <= 10 && recv_len > 0) {
				//��ȡ��Ϣ
				MsgsInit(&message, recv_len - 16);
				Msgsmemcpy(&message, buffer + 16, recv_len - 16);
				switch (Task)
				{
				case JOIN1:
					EPID_Member_Join2(&message, &Mactx);
					Sleep(15);
					send(cliSock, (char*)message.message, message.message_len, 0);
					putMessage(edit.GetHandle(), L">>�ɹ�������������\r\n");
					break;
				case JOIN2:
					EPID_Member_Join_finish(&message, &Mactx);
					cout << "======��ȡ��Ա֤��ɹ�======" << endl;
					putMessage(edit.GetHandle(), L">>��ȡ��Ա֤��\r\n");
					putMessage(edit.GetHandle(), L">>��ʱ ");
					putMessage(edit.GetHandle(), to_wstring((clock() - start) / 2));
					putMessage(edit.GetHandle(), L" ms\r\n\r\n");
					INGroup = true;
					button_free = false;
					break;
				case UPDATE:
					EPID_Member_update_cert(&message, &Mactx);
					cout << "======���³�Ա֤��ɹ�======" << endl;
					putMessage(edit.GetHandle(), L">>��Ա֤����³ɹ�\r\n");
					putMessage(edit.GetHandle(), L">>��ʱ ");
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
					putMessage(edit.GetHandle(), L">>�ٷ���֤ͨ��\r\n\r\n");
					button_free = false;
				}
				else if (memcmp(buffer, "Verify Failed!", 14) == 0) {
					putMessage(edit.GetHandle(), L">>�ٷ���֤ʧ��\r\n\r\n");
					button_free = false;
				}
				else if (memcmp(buffer, "Recevied Failed!", 16) == 0) {
					putMessage(edit.GetHandle(), L">>TCP���ݶ�ʧ��\r\n\r\n");
					button_free = false;
				}
			}


		}
		else if (nrecv < 0)//������յ����ַ���С��0��˵���Ͽ�����
		{
			cout << "��������Ͽ�����" << endl;
			break;
		}
	}
	return 0;
}