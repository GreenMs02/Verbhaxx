#include <Windows.h>
#include <string>
#include <iostream>
#include <istream>
#include <ostream>

// Below are the virtual tables of many verb classes.
// Roblox has a big structure called "CommonVerbs" which contains every single
// verb on the client, but sadly it was declared with __declspec(novtable) so
// we cannot scan for it. Well, we could get a CommonVerb instance in the
// DataModel but I didn't calculate the offset for it... yet.

// By the way, those are TToolVerbs, which is a verb class specifically used
// to make tools (like hopperbins!).


// This is the virtual method that calls ttoolverb->doIt.
#define offset(x) (x - 0x400000 + (DWORD)GetModuleHandleA(NULL))
#define MOUSETOOL_DOIT 0xACCEF0

DWORD rBase = (DWORD)(GetModuleHandleA(NULL));

typedef int(__thiscall* _HammerTool_doIt)(int HammerTool, DWORD Unk);
_HammerTool_doIt MouseTool_doIt = (_HammerTool_doIt)(MOUSETOOL_DOIT - 0x400000 + rBase);

namespace Memory {
	bool Compare(const BYTE *pData, const BYTE *bMask, const char *szMask)
	{
		for (; *szMask; ++szMask, ++pData, ++bMask)
			if (*szMask == 'x' && *pData != *bMask) return 0;
		return (*szMask) == NULL;
	}

	DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, const char *szMask)
	{
		for (int i = 0; i<(int)dwLen; i++)
			if (Compare((BYTE*)(dwAddress + (int)i), bMask, szMask))  return (int)(dwAddress + i);
		return 0;
	}

	int Scan(DWORD mode, char* content, const char* mask, DWORD Offset = 0)
	{
		DWORD PageSize;
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		PageSize = si.dwPageSize;
		MEMORY_BASIC_INFORMATION mi;
		for (DWORD lpAddr = (DWORD)GetModuleHandleA(0) + Offset; lpAddr<0x7FFFFFFF; lpAddr += PageSize)
		{
			DWORD vq = VirtualQuery((void*)lpAddr, &mi, PageSize);
			if (vq == ERROR_INVALID_PARAMETER || vq == 0) break;
			if (mi.Type == MEM_MAPPED) continue;
			if (mi.Protect == mode)
			{
				int addr = FindPattern(lpAddr, PageSize, (PBYTE)content, mask);
				if (addr != 0)
				{
					return addr;
				}
			}
		}
	}

	int QuickScan(DWORD Mode, char* content, char* mask)
	{
		DWORD PageSize;
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		PageSize = si.dwPageSize;
		MEMORY_BASIC_INFORMATION mi;
		for (DWORD lpAddr = (DWORD)GetModuleHandleA(0); lpAddr<0x7FFFFFFF; lpAddr += PageSize)
		{
			int addr = FindPattern(lpAddr, PageSize, (PBYTE)content, mask);
			if (addr != 0)
			{
				return addr;
			}
		}
	}

	bool compare(unsigned long address, unsigned char* pattern, char* mask)
	{
		for (unsigned char* bytes = (unsigned char*)address; *mask; mask++, bytes++, pattern++)
		{
			if (*mask == 'x' && *bytes != *pattern)
			{
				return false;
			}
		}
		return true;
	}

	int findPattern(unsigned long start, unsigned long end, unsigned char* pattern, char* mask, bool vtMode = false)
	{
		MEMORY_BASIC_INFORMATION mbi;
		while (start < end && VirtualQuery((void*)start, &mbi, sizeof(mbi)))
		{
			if ((mbi.State & MEM_COMMIT) && (mbi.Protect & (vtMode ? PAGE_READWRITE : (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) && !(mbi.Protect & PAGE_GUARD))
			{
				for (int i = (int)mbi.BaseAddress; i < (int)mbi.BaseAddress + mbi.RegionSize; i++)
				{
					if (compare(i, pattern, mask))
						return i;
				}
			}
			start += mbi.RegionSize;
		}
		return 0;
	}
}

const char *Verbs[25] = {
	"AdvArrowTool","AdvRotateTool","AdvScaleTool","AdvTranslateTool","AnchorTool","CloneTool","DropperTool","FillTool","FlatTool","GameTool","GlueTool","GrabTool","HammerTool","HingeTool","InletTool","LeftMotorTool","LockTool","MaterialTool","MoveResizeJoinTool","OscillateMotorTool","RightMotorTool","SmoothNoOutlinesTool","StudsTool","UniversalTool","WeldTool"
};

void OpenConsole(const char* title)
{
	DWORD nOldProtect;
	VirtualProtect(&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &nOldProtect);
	*(BYTE*)(&FreeConsole) = 0xC3;
	VirtualProtect(&FreeConsole, 1, nOldProtect, &nOldProtect);

	AllocConsole();
	SetConsoleTitleA(title);
	freopen("CONOUT$", "w", stdout);
	freopen("CONIN$", "r", stdin);
}

int main()
{
	OpenConsole("verbhaxx - Update by GreenMs02 @ V3rmillion");

	// Calculate the offset.
	// I obtain addresses in IDA Pro so the base is 0x400000.
	// I just substract IDA's base from the address then add in
	// Roblox's actual base, which gives us an integer to scan for.
	
	printf("Scanning...\n");
	DWORD AdvArrowTool = offset(0x116FF7C);
	DWORD AdvRotateTool = offset(0x116FF5C);
	DWORD AdvScaleTool = offset(0x116FF9C);
	DWORD AdvTranslateTool = offset(0x116FF3C);
	DWORD AnchorTool = offset(0x117013C);
	DWORD CloneTool = offset(0x117021C);
	DWORD DropperTool = offset(0x11701BC);
	DWORD FillTool = offset(0x117017C);
	DWORD FlatTool = offset(0x116FFDC);
	DWORD GameTool = offset(0x11701DC);
	DWORD GlueTool = offset(0x116FFFC);
	DWORD GrabTool = offset(0x11701FC);
	DWORD HammerTool = offset(0x117023C);
	DWORD HingeTool = offset(0x117009C);
	DWORD InletTool = offset(0x117005C);
	DWORD LeftMotorTool = offset(0x11700DC);
	DWORD LockTool = offset(0x117015C);
	DWORD MaterialTool = offset(0x117019C);
	DWORD MoveResizeJoinTool = offset(0x116FFBC);
	DWORD OscillateMotorTool = offset(0x11700FC);
	DWORD RightMotorTool = offset(0x11700BC);
	DWORD SmoothNoOutlinesTool = offset(0x117011C);
	DWORD StudsTool = offset(0x117003C);
	DWORD UniversalTool = offset(0x117007C);
	DWORD WeldTool = offset(0x117001C);

	int AdvArrowToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&AdvArrowTool, (char*)"xxxx");
	printf("AdvArrowTool: %x\n");
	int AdvRotateToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&AdvRotateTool, (char*)"xxxx");
	printf("AdvRotateTool: %x\n");
	int AdvScaleToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&AdvScaleTool, (char*)"xxxx");
	printf("AdvScaleTool: %x\n");
	int AdvTranslateToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&AdvTranslateTool, (char*)"xxxx");
	printf("AdvTranslateTool: %x\n");
	int AnchorToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&AnchorTool, (char*)"xxxx");
	printf("AnchorTool: %x\n");
	int CloneToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&CloneTool, (char*)"xxxx");
	printf("CloneTool: %x\n");
	int DropperToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&DropperTool, (char*)"xxxx");
	printf("DropperTool: %x\n");
	int FillToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&FillTool, (char*)"xxxx");
	printf("FillTool: %x\n");
	int FlatToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&FlatTool, (char*)"xxxx");
	printf("FlatTool: %x\n");
	int GameToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&GameTool, (char*)"xxxx");
	printf("GameTool: %x\n");
	int GlueToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&GlueTool, (char*)"xxxx");
	printf("GlueTool: %x\n");
	int GrabToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&GrabTool, (char*)"xxxx");
	printf("GrabTool: %x\n");
	int HammerToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&HammerTool, (char*)"xxxx");
	printf("HammerTool: %x\n");
	int HingeToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&HingeTool, (char*)"xxxx");
	printf("HingeTool: %x\n");
	int InletToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&InletTool, (char*)"xxxx");
	printf("InletTool: %x\n");
	int LeftMotorToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&LeftMotorTool, (char*)"xxxx");
	printf("LeftMotorTool: %x\n");
	int LockToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&LockTool, (char*)"xxxx");
	printf("LockTool: %x\n");
	int MaterialToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&MaterialTool, (char*)"xxxx");
	printf("MaterialTool: %x\n");
	int MoveResizeJoinToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&MoveResizeJoinTool, (char*)"xxxx");
	printf("MoveResizeJoinTool: %x\n");
	int OscillateMotorToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&OscillateMotorTool, (char*)"xxxx");
	printf("OscillateMotorTool: %x\n");
	int RightMotorToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&RightMotorTool, (char*)"xxxx");
	printf("RightMotorTool: %x\n");
	int SmoothNoOutlinesToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&SmoothNoOutlinesTool, (char*)"xxxx");
	printf("SmoothNoOutlinesTool: %x\n");
	int StudsToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&StudsTool, (char*)"xxxx");
	printf("StudsTool: %x\n");
	int UniversalToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&UniversalTool, (char*)"xxxx");
	printf("UniversalTool: %x\n");
	int WeldToolA = Memory::findPattern((unsigned long)GetProcessHeap(), 0x7FFFFFFF, (unsigned char*)&WeldTool, (char*)"xxxx");
	printf("WeldTool: %x\n");
	printf("Done!\n");
	system("cls");

	printf("List of tools:\n");
	for (int i = 0; i < 25; ++i)
		printf("%s\n", Verbs[i]);

	printf("\n");
	while (FindWindowW(NULL, L"ROBLOX"))
	{
		printf("->");
		std::string VerbIn;
		std::getline(std::cin, VerbIn);
		if (VerbIn == "AdvArrowTool")
		{
			MouseTool_doIt(AdvArrowToolA, 0);
			continue;
		}
		if (VerbIn == "AdvRotateTool")
		{
			MouseTool_doIt(AdvRotateToolA, 0);
			continue;
		}
		if (VerbIn == "AdvScaleTool")
		{
			MouseTool_doIt(AdvScaleToolA, 0);
			continue;
		}
		if (VerbIn == "AdvTranslateTool")
		{
			MouseTool_doIt(AdvTranslateToolA, 0);
			continue;
		}
		if (VerbIn == "AnchorTool")
		{
			MouseTool_doIt(AnchorToolA, 0);
			continue;
		}
		if (VerbIn == "CloneTool")
		{
			MouseTool_doIt(CloneToolA, 0);
			continue;
		}
		if (VerbIn == "DropperTool")
		{
			MouseTool_doIt(DropperToolA, 0);
			continue;
		}
		if (VerbIn == "FillTool")
		{
			MouseTool_doIt(FillToolA, 0);
			continue;
		}
		if (VerbIn == "FlatTool")
		{
			MouseTool_doIt(FlatToolA, 0);
			continue;
		}
		if (VerbIn == "GameTool")
		{
			MouseTool_doIt(GameToolA, 0);
			continue;
		}
		if (VerbIn == "GlueTool")
		{
			MouseTool_doIt(GlueToolA, 0);
			continue;
		}
		if (VerbIn == "GrabTool")
		{
			MouseTool_doIt(GrabToolA, 0);
			continue;
		}
		if (VerbIn == "HammerTool")
		{
			MouseTool_doIt(HammerToolA, 0);
			continue;
		}
		if (VerbIn == "HingeTool")
		{
			MouseTool_doIt(HingeToolA, 0);
			continue;
		}
		if (VerbIn == "InletTool")
		{
			MouseTool_doIt(InletToolA, 0);
			continue;
		}
		if (VerbIn == "LeftMotorTool")
		{
			MouseTool_doIt(LeftMotorToolA, 0);
			continue;
		}
		if (VerbIn == "LockTool")
		{
			MouseTool_doIt(LockToolA, 0);
			continue;
		}
		if (VerbIn == "MaterialTool")
		{
			MouseTool_doIt(MaterialToolA, 0);
			continue;
		}
		if (VerbIn == "MoveResizeJoinTool")
		{
			MouseTool_doIt(MoveResizeJoinToolA, 0);
			continue;
		}
		if (VerbIn == "OscillateMotorTool")
		{
			MouseTool_doIt(OscillateMotorToolA, 0);
			continue;
		}
		if (VerbIn == "RightMotorTool")
		{
			MouseTool_doIt(RightMotorToolA, 0);
			continue;
		}
		if (VerbIn == "SmoothNoOutlinesTool")
		{
			MouseTool_doIt(SmoothNoOutlinesToolA, 0);
			continue;
		}
		if (VerbIn == "StudsTool")
		{
			MouseTool_doIt(StudsToolA, 0);
			continue;
		}
		if (VerbIn == "UniversalTool")
		{
			MouseTool_doIt(UniversalToolA, 0);
			continue;
		}
		if (VerbIn == "WeldTool")
		{
			MouseTool_doIt(WeldToolA, 0);
			continue;
		}

		printf("Invalid verb!\n");
	}
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH: {
		DisableThreadLibraryCalls(hModule);
		CreateThread(0, NULL, (LPTHREAD_START_ROUTINE)&main, NULL, NULL, NULL);
		break;
	};
	};
	return true;
};