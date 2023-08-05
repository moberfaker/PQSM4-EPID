/**
 * @file	SysCheckBox.h
 * @brief	HiSysGUI �ؼ���֧����ѡ��
 * @author	huidong
*/

#pragma once

#include "SysControlBase.h"

namespace HiEasyX
{
	/**
	 * @brief ϵͳ��ѡ��ؼ�
	*/
	class SysCheckBox : public SysControlBase
	{
	private:
		bool m_bChecked = false;
		void (*m_pFunc)(bool checked) = nullptr;

	protected:

		void RealCreate(HWND hParent) override;

	public:

		SysCheckBox();

		SysCheckBox(HWND hParent, RECT rct, std::wstring strText = L"");

		SysCheckBox(HWND hParent, int x, int y, int w, int h, std::wstring strText = L"");

		LRESULT UpdateMessage(UINT msg, WPARAM wParam, LPARAM lParam, bool& bRet) override;

		/**
		 * @brief ע������Ϣ
		 * @param[in] pFunc ��Ϣ��Ӧ����
		*/
		void RegisterMessage(void (*pFunc)(bool checked));

		/**
		 * @brief ��ȡѡ��״̬
		*/
		bool IsChecked() const { return m_bChecked; }

		void Check(bool check);
	};
}