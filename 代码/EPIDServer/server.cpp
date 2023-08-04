#include"pch.h"//Ԥ����ͷ
#include<iostream>
#include<Winsock2.h>//socketͷ�ļ�
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


//����ϵͳ�ṩ��socket��̬���ӿ�
#pragma comment(lib,"ws2_32.lib")   //socket��

//==============================ȫ�ֱ�����===================================
const int BUFFER_SIZE = 400000;//��������С
int RECV_TIMEOUT = 20;//������Ϣ��ʱ
int SEND_TIMEOUT = 20;//������Ϣ��ʱ
const int WAIT_TIME = 20;//ÿ���ͻ��˵ȴ��¼���ʱ�䣬��λ����
const int MAX_LINK_NUM = 10;//��������������
SOCKET cliSock[MAX_LINK_NUM];//�ͻ����׽��� 0��Ϊ�����
SOCKADDR_IN cliAddr[MAX_LINK_NUM];//�ͻ��˵�ַ
WSAEVENT cliEvent[MAX_LINK_NUM];//�ͻ����¼� 0��Ϊ�����,�������ó����һ���ֵȴ�������һ���ֵ��źš����磬�����ݴ��׽��ֱ�Ϊ����ʱ��winsock ��Ὣ�¼�����Ϊ�ź�״̬
int total = 0;//��ǰ�Ѿ����ӵĿͷ��˷�����
int total_serve = 0;	//��ǰͨ����ǩ��

//==============================��������===================================
DWORD WINAPI servEventThread(LPVOID IpParameter);//�������˴����߳�
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
	// �ڹ��λ�ú�����ı�
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

/* ========================================���ݿ�======================================== */
// ȺID��
int IDPool = 0;
int T = sizeof(GP_MANAGER_CTX);
GP_MANAGER_CTX Gpctx[1];
// ��Ϣ����
Msgs message;

hiex::SysEdit edit;
/* ========================================���ݿ�======================================== */


int main()
{
	/* ================ �����뽻�� ================ */
	hiex::Window wnd(400 + 80, 600, SHOWCONSOLES, L"���׮���������б�");

	edit.PreSetStyle({ true, false, true });
	edit.Create(wnd.GetHandle(), 20, 20 + 20, 360 + 80, 560 - 20, L"");
	edit.SetFont(24, 2, L"΢���ź�");
	putMessage(edit.GetHandle(), L" ��������\t\t��ǰ����\t\t�����ͺ�\t\t���ʱ��\r\n");
	putMessage(edit.GetHandle(), L"==============================================\r\n");
	edit.SetFont(18, 0, L"΢���ź�");
	edit.ReadOnly(true);
	/* ================ �����뽻�� ================ */

	// Ⱥ0��ʼ��
	EPID_Group_Init(&Gpctx[0], EPID_L1, &IDPool);

	//1����ʼ��socket��
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//2������socket
	SOCKET servSock = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN servAddr;
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	//�˿ں�����Ϊ4221
	servAddr.sin_port = htons(4221);
	//3���󶨷����
	bind(servSock, (SOCKADDR*)&servAddr, sizeof(servAddr));
	WSAEVENT servEvent = WSACreateEvent();
	WSAEventSelect(servSock, servEvent, FD_ALL_EVENTS);
	cliSock[0] = servSock;
	cliEvent[0] = servEvent;
	//5����������
	//�������г���Ϊ10
	listen(servSock, 10);
	//6�������������ӵ��߳�
	CloseHandle(CreateThread(NULL, 0, servEventThread, (LPVOID)&servSock, 0, 0));
	cout << "\n\n================Ⱥ����˿���================" << endl;
	cout << "����	1.������Ⱥ  2.����֤��  3.����˽Կ" << endl;
	while (1)
	{
		char contentBuf[BUFFER_SIZE / 400] = { 0 };
		char sendBuf[BUFFER_SIZE / 400] = { 0 };
		cin.getline(contentBuf, sizeof(contentBuf));
		sprintf(sendBuf, "[Ⱥ����Ա]%s", contentBuf);
		//���͹���Ա��Ϣ
		for (int j = 1; j <= total; j++)
			send(cliSock[j], sendBuf, sizeof(sendBuf), 0);
	}
	WSACleanup();
	return 0;
}


DWORD WINAPI servEventThread(LPVOID IpParameter) //���������߳�
{
	//���̸߳��������˺͸����ͻ��˷������¼�
	//������Ĳ�����ʼ��
	SOCKET servSock = *(SOCKET*)IpParameter;//LPVOIDΪ��ָ�����ͣ���Ҫ��ת��SOCKET���������ã�����ʹ�ô����SOCKET
	while (1) //��ִͣ��
	{
		for (int i = 0; i < total + 1; i++)//i�����������ڼ����¼����ն�
		{
			//����һ���ͻ������ӣ�total==1��ѭ�����Σ������ͻ��˺ͷ����
			//��ÿһ���նˣ��ͻ��˺ͷ���ˣ����鿴�Ƿ����¼����ȴ�WAIT_TIME����
			int index = WSAWaitForMultipleEvents(1, &cliEvent[i], false, WAIT_TIME, 0);

			index -= WSA_WAIT_EVENT_0;//��ʱindexΪ�����¼����ն��±�

			if (index == WSA_WAIT_TIMEOUT || index == WSA_WAIT_FAILED)
			{
				continue;//���������߳�ʱ�����������ն�
			}

			else if (index == 0)
			{
				WSANETWORKEVENTS networkEvents;
				WSAEnumNetworkEvents(cliSock[i], cliEvent[i], &networkEvents);//�鿴��ʲô�¼�

				//�¼�ѡ��
				if (networkEvents.lNetworkEvents & FD_ACCEPT)//������accept�¼����˴���λ�������룩
				{
					if (networkEvents.iErrorCode[FD_ACCEPT_BIT] != 0)
					{
						cout << "����ʱ�������󣬴������" << networkEvents.iErrorCode[FD_ACCEPT_BIT] << endl;
						continue;
					}
					//��������
					if (total + 1 < MAX_LINK_NUM)//������һ���ͻ�����ȻС�����������������ܸ�����
					{
						//totalΪ�����ӿͻ�������
						int nextIndex = total + 1;//������¿ͻ��˵��±�
						int addrLen = sizeof(SOCKADDR);
						SOCKET newSock = accept(servSock, (SOCKADDR*)&cliAddr[nextIndex], &addrLen);
						if (newSock != INVALID_SOCKET)
						{
							//���÷��ͺͽ���ʱ��
							/*setsockopt(newSock, SOL_SOCKET, SO_SNDTIMEO, (const char*) & SEND_TIMEOUT, sizeof(SEND_TIMEOUT));
							setsockopt(newSock, SOL_SOCKET, SO_SNDTIMEO, (const char*) &RECV_TIMEOUT, sizeof(RECV_TIMEOUT));*/
							//���¿ͻ��˷���socket
							cliSock[nextIndex] = newSock;
							//�¿ͻ��˵ĵ�ַ�Ѿ�����cliAddr[nextIndex]����
							//Ϊ�¿ͻ��˰��¼�����,ͬʱ���ü�����close��read��write
							WSAEVENT newEvent = WSACreateEvent();
							WSAEventSelect(cliSock[nextIndex], newEvent, FD_CLOSE | FD_READ | FD_WRITE);
							cliEvent[nextIndex] = newEvent;
							total++;//�ͻ�������������
							cout << "#" << nextIndex << "��Ա��IP��" << inet_ntoa(cliAddr[nextIndex].sin_addr) << ")����Ⱥ" << endl;

						}
					}

				}
				else if (networkEvents.lNetworkEvents & FD_CLOSE)//�ͻ��˱��رգ����Ͽ�����
				{

					//i��ʾ�ѹرյĿͻ����±�
					total--;
					cout << "#" << i << "��Ա��IP��" << inet_ntoa(cliAddr[i].sin_addr) << ")�˳�������" << endl;
					//�ͷ�����ͻ��˵���Դ
					closesocket(cliSock[i]);
					WSACloseEvent(cliEvent[i]);

					//�������,��˳���ɾ��Ԫ��
					for (int j = i; j < total; j++)
					{
						cliSock[j] = cliSock[j + 1];
						cliEvent[j] = cliEvent[j + 1];
						cliAddr[j] = cliAddr[j + 1];
					}


				}
				else if (networkEvents.lNetworkEvents & FD_READ)//���յ���Ϣ
				{

					char buffer[BUFFER_SIZE] = { 0 };//�ַ������������ڽ�����Ϣ
					for (int j = 1; j <= total; j++)
					{
						int recvBufferSize;
						int len = sizeof(recvBufferSize);
						getsockopt(cliSock[j], SOL_SOCKET, SO_RCVBUF, (char*)&recvBufferSize, &len);
						int totalBytesReceived = 0;
						int bytesReceived;

						int nrecv = recv(cliSock[j], buffer, sizeof(buffer), 0);//nrecv�ǽ��յ����ֽ���
						if (nrecv > 0)//������յ����ַ�������0
						{
							//������Ϣͷ
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
								//	// �����ﴦ����յ�������
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
									cout << "[#" << j << "]" << "������Ⱥ..." << endl;
									EPID_Group_Join1(&message, Gpctx);
									sprintf(buffer, "[Ⱥ����Ա]���ͣ�Ⱥ��Կ����ս��\n");
									send(cliSock[j], buffer, sizeof(buffer), 0);
									send(cliSock[j], (const char*)message.message, message.message_len, 0);
									break;
								case JOIN2:
									cout << "[#" << j << "]" << "��Ӧ��ս..." << endl;
									EPID_Group_Join2(&message, Gpctx);
									sprintf(buffer, "[Ⱥ����Ա]�䲼֤��\n");
									send(cliSock[j], buffer, sizeof(buffer), 0);
									send(cliSock[j], (const char*)message.message, message.message_len, 0);
									break;
								case UPDATE:
									cout << "[#" << j << "]" << "�������֤��..." << endl;
									EPID_Manager_updaet_cert(&message, Gpctx);
									send(cliSock[j], (const char*)message.message, message.message_len, 0);
									break;
								case REVOKEKEY:
									cout << "[#" << j << "]" << "�˳�Ⱥ��..." << endl;
									EPID_Manager_Exit_Group(&message, Gpctx);
									break;
								case SIGN:
									cout << "[#" << j << "]" << "����ǩ����֤..." << endl;
									int ret;
									uint8_t* text;
									text = NULL;
									printf("%d", nrecv);
									ret = EPID_Verify(&text, &message, Gpctx->MemSize, Gpctx->ComList.X);
									printf("ǩ����Ϣ�� %s\n", text);	//�˴�Ϊ�̶������б����
									text = get_sigtext(text, strlen((const char*)text));
									if (ret == 0) {
										send(cliSock[j], "Verify Success!", 16, 0);
										total_serve++;
										putMessage(edit.GetHandle(), L"  ��");
										putMessage(edit.GetHandle(), to_wstring(total_serve));
										putMessage(edit.GetHandle(), L"��\t\t");

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