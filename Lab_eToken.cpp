#include "Lab_eToken.h"
#include <Windows.h>
#include "lib/cryptoki.h"
//#include "lib/otp-pkcs11.h"
//#include "lib/eTSAPI.h"
//#include "lib/pkcs11.h"
//#include "lib/pkcs11t.h"
#include "lib/eTPkcs11.h"

using namespace labetoken;

[STAThreadAttribute]
int main(array<System::String^>^ args)
{


	FreeConsole();
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	Application::Run(gcnew Lab_eToken());

	return 0;
}

