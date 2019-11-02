#pragma once
#include <Windows.h>
#include "lib/cryptoki.h"
#include "lib/eTPkcs11.h"

namespace labetoken {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Runtime::InteropServices;

	const int MAX_TEXT_LEN = 512;

	CK_C_GetFunctionList pGFL;
	CK_RV rv;
	CK_INFO info;
	CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_ULONG ulCount;
	CK_SLOT_ID_PTR pSlotIList;
	CK_SESSION_HANDLE hSession;
	CK_FUNCTION_LIST_PTR pFunctionList;
	CK_UTF8CHAR pin[] = { "1234567890" };
	CK_OBJECT_HANDLE hKey;

	CK_BYTE plainText[MAX_TEXT_LEN];
	CK_ULONG plainTextLength = sizeof(plainText);
	CK_BYTE encryptedText[MAX_TEXT_LEN];
	CK_ULONG encryptedTextLength = sizeof(encryptedText);
	CK_BYTE hash[16];
	CK_ULONG hashLength = 16;
	CK_BYTE encIV[8];
	CK_MECHANISM encryptMechanism = { CKM_DES_CBC, encIV, sizeof(encIV)  };
	CK_MECHANISM keygenMechanism = { CKM_DES_KEY_GEN, NULL, 0 };
	CK_MECHANISM hashMechanism = { CKM_MD5, NULL, 0 };


	public ref class Lab_eToken : public System::Windows::Forms::Form
	{
	public:
		Lab_eToken(void)
		{
			InitializeComponent();

			HMODULE hLib = LoadLibrary(TEXT("eTpkcs11.dll"));

			if (hLib == NULL) {
				System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to load eToken library");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			(FARPROC&)pGFL = GetProcAddress(hLib, "C_GetFunctionList");

			if (pGFL == NULL) {
				System::Windows::Forms::DialogResult status = MessageBox::Show("GetFunctionList is not found");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			if (pGFL(&pFunctionList) != CKR_OK) {
				System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to get function list");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			rv = pFunctionList->C_Initialize(NULL_PTR);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status =
					MessageBox::Show("Unable to initialize Cryptoki library", "Error");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL_PTR, &ulCount);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status =
					MessageBox::Show("Unable to get slots. Try to replug eToken reader", "Error");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			pSlotIList = (CK_SLOT_ID_PTR)malloc(0);
			rv = pFunctionList->C_GetSlotList(CK_TRUE, pSlotIList, &ulCount);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status =
					MessageBox::Show("Unable to get slots with tokens. Try to replug eToken reader", "Error");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			rv = pFunctionList->C_OpenSession(*pSlotIList, flags, NULL_PTR, NULL_PTR, &hSession);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to open session");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			rv = pFunctionList->C_Login(hSession, CKU_USER, pin, sizeof(pin) - 1);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to login");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			rv = pFunctionList->C_GenerateKey(hSession, &keygenMechanism, NULL_PTR, 0, &hKey);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to generate session key");

				if (status == System::Windows::Forms::DialogResult::OK) {
					exit(1);
				}
			}

			textBoxSessionKey->Text = hKey.ToString();
		}

	protected:
		~Lab_eToken()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::RichTextBox^ richTextBoxPlainText;
	private: System::Windows::Forms::Button^ buttonAboutToken;
	private: System::Windows::Forms::Button^ buttonEncrypt;
	private: System::Windows::Forms::Label^ labelPlainText;
	private: System::Windows::Forms::Label^ labelEncryptedText;
	private: System::Windows::Forms::RichTextBox^ richTextBoxEncryptedText;
	private: System::Windows::Forms::Button^ buttonDecrypt;
	private: System::Windows::Forms::RichTextBox^ richTextBoxDecryptedText;
	private: System::Windows::Forms::TextBox^ textBoxSessionKey;
	private: System::Windows::Forms::Label^ labelSessionKey;
	private: System::Windows::Forms::Label^ labelDecryptedText;
	private: System::Windows::Forms::RichTextBox^ richTextBox1;
	private: System::Windows::Forms::Button^ button1;




	protected:

	private:
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code

		void InitializeComponent(void)
		{
			this->richTextBoxPlainText = (gcnew System::Windows::Forms::RichTextBox());
			this->buttonAboutToken = (gcnew System::Windows::Forms::Button());
			this->buttonDecrypt = (gcnew System::Windows::Forms::Button());
			this->buttonEncrypt = (gcnew System::Windows::Forms::Button());
			this->labelPlainText = (gcnew System::Windows::Forms::Label());
			this->labelEncryptedText = (gcnew System::Windows::Forms::Label());
			this->richTextBoxEncryptedText = (gcnew System::Windows::Forms::RichTextBox());
			this->richTextBoxDecryptedText = (gcnew System::Windows::Forms::RichTextBox());
			this->textBoxSessionKey = (gcnew System::Windows::Forms::TextBox());
			this->labelSessionKey = (gcnew System::Windows::Forms::Label());
			this->labelDecryptedText = (gcnew System::Windows::Forms::Label());
			this->richTextBox1 = (gcnew System::Windows::Forms::RichTextBox());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->SuspendLayout();
			// 
			// richTextBoxPlainText
			// 
			this->richTextBoxPlainText->Location = System::Drawing::Point(18, 43);
			this->richTextBoxPlainText->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->richTextBoxPlainText->Name = L"richTextBoxPlainText";
			this->richTextBoxPlainText->Size = System::Drawing::Size(320, 70);
			this->richTextBoxPlainText->TabIndex = 0;
			this->richTextBoxPlainText->Text = L"";
			// 
			// buttonAboutToken
			// 
			this->buttonAboutToken->Location = System::Drawing::Point(562, 409);
			this->buttonAboutToken->Name = L"buttonAboutToken";
			this->buttonAboutToken->Size = System::Drawing::Size(108, 35);
			this->buttonAboutToken->TabIndex = 6;
			this->buttonAboutToken->Text = L"About token";
			this->buttonAboutToken->UseVisualStyleBackColor = true;
			this->buttonAboutToken->Click += gcnew System::EventHandler(this, &Lab_eToken::buttonAboutToken_Click);
			// 
			// buttonDecrypt
			// 
			this->buttonDecrypt->Location = System::Drawing::Point(141, 409);
			this->buttonDecrypt->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->buttonDecrypt->Name = L"buttonDecrypt";
			this->buttonDecrypt->Size = System::Drawing::Size(112, 35);
			this->buttonDecrypt->TabIndex = 9;
			this->buttonDecrypt->Text = L"Decrypt";
			this->buttonDecrypt->UseVisualStyleBackColor = true;
			this->buttonDecrypt->Click += gcnew System::EventHandler(this, &Lab_eToken::buttonDecrypt_Click);
			// 
			// buttonEncrypt
			// 
			this->buttonEncrypt->Location = System::Drawing::Point(18, 409);
			this->buttonEncrypt->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->buttonEncrypt->Name = L"buttonEncrypt";
			this->buttonEncrypt->Size = System::Drawing::Size(112, 35);
			this->buttonEncrypt->TabIndex = 1;
			this->buttonEncrypt->Text = L"Encrypt";
			this->buttonEncrypt->UseVisualStyleBackColor = true;
			this->buttonEncrypt->Click += gcnew System::EventHandler(this, &Lab_eToken::buttonEncrypt_Click);
			// 
			// labelPlainText
			// 
			this->labelPlainText->AutoSize = true;
			this->labelPlainText->Location = System::Drawing::Point(18, 18);
			this->labelPlainText->Margin = System::Windows::Forms::Padding(4, 0, 4, 0);
			this->labelPlainText->Name = L"labelPlainText";
			this->labelPlainText->Size = System::Drawing::Size(113, 20);
			this->labelPlainText->TabIndex = 3;
			this->labelPlainText->Text = L"Text to encrypt";
			// 
			// labelEncryptedText
			// 
			this->labelEncryptedText->AutoSize = true;
			this->labelEncryptedText->Location = System::Drawing::Point(20, 134);
			this->labelEncryptedText->Margin = System::Windows::Forms::Padding(4, 0, 4, 0);
			this->labelEncryptedText->Name = L"labelEncryptedText";
			this->labelEncryptedText->Size = System::Drawing::Size(111, 20);
			this->labelEncryptedText->TabIndex = 7;
			this->labelEncryptedText->Text = L"Encrypted text";
			// 
			// richTextBoxEncryptedText
			// 
			this->richTextBoxEncryptedText->Location = System::Drawing::Point(18, 158);
			this->richTextBoxEncryptedText->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->richTextBoxEncryptedText->Name = L"richTextBoxEncryptedText";
			this->richTextBoxEncryptedText->ReadOnly = true;
			this->richTextBoxEncryptedText->Size = System::Drawing::Size(320, 70);
			this->richTextBoxEncryptedText->TabIndex = 8;
			this->richTextBoxEncryptedText->Text = L"";
			// 
			// richTextBoxDecryptedText
			// 
			this->richTextBoxDecryptedText->Location = System::Drawing::Point(18, 280);
			this->richTextBoxDecryptedText->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->richTextBoxDecryptedText->Name = L"richTextBoxDecryptedText";
			this->richTextBoxDecryptedText->ReadOnly = true;
			this->richTextBoxDecryptedText->Size = System::Drawing::Size(320, 70);
			this->richTextBoxDecryptedText->TabIndex = 10;
			this->richTextBoxDecryptedText->Text = L"";
			// 
			// textBoxSessionKey
			// 
			this->textBoxSessionKey->Location = System::Drawing::Point(474, 42);
			this->textBoxSessionKey->Name = L"textBoxSessionKey";
			this->textBoxSessionKey->ReadOnly = true;
			this->textBoxSessionKey->Size = System::Drawing::Size(196, 26);
			this->textBoxSessionKey->TabIndex = 11;
			// 
			// labelSessionKey
			// 
			this->labelSessionKey->AutoSize = true;
			this->labelSessionKey->Location = System::Drawing::Point(374, 46);
			this->labelSessionKey->Name = L"labelSessionKey";
			this->labelSessionKey->Size = System::Drawing::Size(94, 20);
			this->labelSessionKey->TabIndex = 12;
			this->labelSessionKey->Text = L"Session key";
			// 
			// labelDecryptedText
			// 
			this->labelDecryptedText->AutoSize = true;
			this->labelDecryptedText->Location = System::Drawing::Point(20, 255);
			this->labelDecryptedText->Name = L"labelDecryptedText";
			this->labelDecryptedText->Size = System::Drawing::Size(112, 20);
			this->labelDecryptedText->TabIndex = 13;
			this->labelDecryptedText->Text = L"Decrypted text";
			// 
			// richTextBox1
			// 
			this->richTextBox1->Location = System::Drawing::Point(474, 102);
			this->richTextBox1->Name = L"richTextBox1";
			this->richTextBox1->Size = System::Drawing::Size(196, 96);
			this->richTextBox1->TabIndex = 14;
			this->richTextBox1->Text = L"";
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(271, 409);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(75, 35);
			this->button1->TabIndex = 15;
			this->button1->Text = L"button1";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &Lab_eToken::button1_Click);
			// 
			// Lab_eToken
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(9, 20);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(687, 462);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->richTextBox1);
			this->Controls->Add(this->labelDecryptedText);
			this->Controls->Add(this->labelSessionKey);
			this->Controls->Add(this->textBoxSessionKey);
			this->Controls->Add(this->richTextBoxDecryptedText);
			this->Controls->Add(this->buttonDecrypt);
			this->Controls->Add(this->richTextBoxEncryptedText);
			this->Controls->Add(this->labelEncryptedText);
			this->Controls->Add(this->buttonAboutToken);
			this->Controls->Add(this->labelPlainText);
			this->Controls->Add(this->buttonEncrypt);
			this->Controls->Add(this->richTextBoxPlainText);
			this->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->Name = L"Lab_eToken";
			this->Text = L"Lab_eToken";
			this->FormClosing += gcnew System::Windows::Forms::FormClosingEventHandler(this, &Lab_eToken::Lab_eToken_FormClosing);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion

	private: System::Void buttonEncrypt_Click(System::Object^ sender, EventArgs^ e) {
		for (int i = 0; i < MAX_TEXT_LEN; i++) {
			plainText[i] = 0;
		}

		rv = pFunctionList->C_EncryptInit(hSession, &encryptMechanism, hKey);

		if (rv != CKR_OK) {
			System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to initialize encryption");

			if (status == System::Windows::Forms::DialogResult::OK) {
				exit(1);
			}
		}

		String^ plainTextBox = this->richTextBoxPlainText->Text;

		for (int i = 0; i < plainTextBox->Length; i++) {
			plainText[i] += (char)plainTextBox[i];
		}

		rv = pFunctionList->C_Encrypt(hSession, plainText, plainTextLength, encryptedText, &encryptedTextLength);

		if (rv != CKR_OK)
		{
			System::Windows::Forms::DialogResult status = 
				MessageBox::Show("Unable to encrypt data");
		}
		else {
			String^ str = gcnew String(reinterpret_cast<char*>(encryptedText));

			richTextBoxEncryptedText->Text = str;
		}
	}

	private: System::Void buttonDecrypt_Click(System::Object^ sender, System::EventArgs^ e) {
		rv = pFunctionList->C_DecryptInit(hSession, &encryptMechanism, hKey);

		if (rv != CKR_OK) {
			System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to initialize decryption");

			if (status == System::Windows::Forms::DialogResult::OK) {
				exit(1);
			}
		}

		rv = pFunctionList->C_Decrypt(hSession, encryptedText, encryptedTextLength, plainText, &plainTextLength);

		if (rv != CKR_OK)
		{
			System::Windows::Forms::DialogResult status =  MessageBox::Show("Unable to decrypt data");
		}
		else {
			richTextBoxDecryptedText->Text = gcnew String(reinterpret_cast<const char*>(plainText));
		}
	}

	private: System::Void buttonAboutToken_Click(System::Object^ sender, System::EventArgs^ e) {
		this->GetSlotInfo();
		this->GetTokenInfo();

		String^ slotDescription = gcnew String(reinterpret_cast<char*>(slotInfo.slotDescription));
				slotDescription = slotDescription->Substring(0, 32);
		String^ slotManunfacturer = gcnew String(reinterpret_cast<char*>(slotInfo.manufacturerID));
				slotManunfacturer = slotManunfacturer->Substring(0, 32);
		String^ serialNumber  = gcnew String(reinterpret_cast<char*>(tokenInfo.serialNumber));
				serialNumber  = serialNumber->Substring(0, 16);
		String^ label		  = gcnew String(reinterpret_cast<char*>(tokenInfo.label));
				label = label->Substring(0, 32);
		String^ model		  = gcnew String(reinterpret_cast<char*>(tokenInfo.model));
				model = model->Substring(0, 16);
		String^ tokenManunfacturer = gcnew String(reinterpret_cast<char*>(tokenInfo.manufacturerID));
				tokenManunfacturer = tokenManunfacturer->Substring(0, 32);

		System::Windows::Forms::DialogResult status =
			MessageBox::Show(
				"Slot information:\n"
				"    Description:    " + slotDescription + "\n"
				"    Manufacturer:    " + slotManunfacturer + "\n\n"
				"Token information:\n"
				"    Serial ¹:    " + serialNumber + "\n"
				"    Label:    " + label + "\n"
				"    Model:    " + model + "\n"
				"    Manufacturer:    " + tokenManunfacturer + "\n",
				"About"
			);
	}

	private: System::Void Lab_eToken_FormClosing(System::Object^ sender, System::Windows::Forms::FormClosingEventArgs^ e)
	{
		pFunctionList->C_Logout(hSession);
		pFunctionList->C_CloseSession(hSession);
		pFunctionList->C_Finalize(NULL_PTR);
	}

	// Non win form methods
	private:
		void GetSlotInfo() {
			rv = pFunctionList->C_GetSlotInfo(*pSlotIList, &slotInfo);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status = 
					MessageBox::Show(
						"Unable to get slot information. Try to replug eToken reader",
						"Error",
						MessageBoxButtons::RetryCancel
					);

				if (status == System::Windows::Forms::DialogResult::Retry) {
					this->GetSlotInfo();
				}
				else {
					exit(1);
				}
			}
		}

		void GetTokenInfo() {
			rv = pFunctionList->C_GetTokenInfo(*pSlotIList, &tokenInfo);

			if (rv != CKR_OK) {
				System::Windows::Forms::DialogResult status = MessageBox::Show(
					"Unable to get token information",
					"Error",
					MessageBoxButtons::RetryCancel
				);

				if (status == System::Windows::Forms::DialogResult::Retry) {
					this->GetTokenInfo();
				}
				else {
					exit(1);
				}
			}
		}
private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {
	for (int i = 0; i < MAX_TEXT_LEN; i++) {
		plainText[i] = 0;
	}

	rv = pFunctionList->C_DigestInit(hSession, &hashMechanism);

	if (rv != CKR_OK) {
		System::Windows::Forms::DialogResult status = MessageBox::Show("Unable to initialize encryption");

		if (status == System::Windows::Forms::DialogResult::OK) {
			exit(1);
		}
	}

	String^ plainTextBox = this->richTextBoxPlainText->Text;

	for (int i = 0; i < plainTextBox->Length; i++) {
		plainText[i] += (char)plainTextBox[i];
	}

	rv = pFunctionList->C_Digest(hSession, plainText, plainTextLength, hash, &hashLength);

	if (rv != CKR_OK)
	{
		System::Windows::Forms::DialogResult status =
			MessageBox::Show("Unable to hash data");
	}
	else {
		String^ str = gcnew String(reinterpret_cast<char*>(hash));

		richTextBox1->Text = str;
	}
}
};
}
