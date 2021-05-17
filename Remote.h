#pragma once

#include <Windows.h>




template<class T>
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T& value 
) {
	SIZE_T nBytesRead = 0;
	if (!ReadProcessMemory(hProc, (LPCVOID)offset, &value, sizeof(T), &nBytesRead)) {
		DWORD err = GetLastError();
		_tprintf(_T("ReadRemote failed with code 0x%x"), err);
		return err;
	}

	return 0;
}

//Read untill terminator or up to amount
template<class T>
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T* value,
	_Out_ DWORD& amount
) {

	ULONG_PTR p = offset;
	DWORD counter = 0;
	T zero = {};

	for (;;) {
		T current;

		//read single unit
		if( (ReadRemote<T>(hProc, p, current)) != 0) return 1;
		value[counter] = current;
		counter++;

		if (0 != amount && counter == amount) break;

		p += sizeof(T);
		if (0 == amount && 0 == memcmp(&current, &zero, sizeof(T))) break;
	}

	counter--;
	amount = counter;
	return 0;
}



template<class T>
DWORD WriteRemote(
    _In_ HANDLE hProc,
    _In_ ULONG_PTR offset,
    _In_ const T& value
) {
    SIZE_T nBytesWritten = 0;
    if (!WriteProcessMemory(hProc, (LPVOID)offset, &value, sizeof(T), &nBytesWritten)) {
        DWORD err = GetLastError();
        _tprintf(_T("WriteRemote failed with code 0x%x"), err);
        return err;
    }

    return 0;
}