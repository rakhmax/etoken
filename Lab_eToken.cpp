#include "Lab_eToken.h"
#include <Windows.h>
#include "lib/cryptoki.h"
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

