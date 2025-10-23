// CredentialGuardChecker.cpp
// Outil de vérification VBS/Credential Guard/HVCI et attestation TPM
// Ayi NEDJIMI Consultants - WinToolsSuite

#define UNICODE
#define _UNICODE
#define _WIN32_DCOM

#include <windows.h>
#include <commctrl.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <tbs.h>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

struct SecurityFeature {
    std::wstring feature;
    std::wstring state;
    std::wstring prerequisites;
    std::wstring status;
    std::wstring recommendations;
};

// Globals
HWND g_hwndMain = nullptr;
HWND g_hwndListView = nullptr;
HWND g_hwndStatus = nullptr;
std::vector<SecurityFeature> g_features;

// Logging
void LogMessage(const std::wstring& msg) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"CredentialGuardChecker.log";

    std::wofstream logFile(logPath, std::ios::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << std::setfill(L'0')
                << std::setw(4) << st.wYear << L"-"
                << std::setw(2) << st.wMonth << L"-"
                << std::setw(2) << st.wDay << L" "
                << std::setw(2) << st.wHour << L":"
                << std::setw(2) << st.wMinute << L":"
                << std::setw(2) << st.wSecond << L" - "
                << msg << std::endl;
        logFile.close();
    }
}

std::wstring GetStateString(DWORD state) {
    switch (state) {
        case 0: return L"Désactivé";
        case 1: return L"Activé (pas en cours d'exécution)";
        case 2: return L"Activé et en cours d'exécution";
        default: return L"État inconnu";
    }
}

bool CheckTPMPresence() {
    TBS_CONTEXT_PARAMS2 contextParams = {};
    contextParams.version = TPM_VERSION_20;
    contextParams.includeTpm12 = 1;
    contextParams.includeTpm20 = 1;

    TBS_HCONTEXT hContext = 0;
    TBS_RESULT result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hContext);

    if (result == TBS_SUCCESS) {
        TPM_DEVICE_INFO deviceInfo = {};
        UINT32 resultSize = sizeof(deviceInfo);

        result = Tbsi_GetDeviceInfo(sizeof(deviceInfo), &deviceInfo);
        Tbsip_Context_Close(hContext);

        return (result == TBS_SUCCESS);
    }

    return false;
}

void CheckDeviceGuardRegistry(std::wstring& report) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                 L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                                 0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        DWORD enableVirtualizationBasedSecurity = 0;
        DWORD requirePlatformSecurityFeatures = 0;
        DWORD size = sizeof(DWORD);

        RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", nullptr, nullptr,
                        (LPBYTE)&enableVirtualizationBasedSecurity, &size);

        size = sizeof(DWORD);
        RegQueryValueExW(hKey, L"RequirePlatformSecurityFeatures", nullptr, nullptr,
                        (LPBYTE)&requirePlatformSecurityFeatures, &size);

        RegCloseKey(hKey);

        report += L"\r\n--- Configuration Registre DeviceGuard ---\r\n";
        report += L"EnableVirtualizationBasedSecurity: " + std::to_wstring(enableVirtualizationBasedSecurity);
        report += (enableVirtualizationBasedSecurity == 1) ? L" (Activé)\r\n" : L" (Désactivé)\r\n";

        report += L"RequirePlatformSecurityFeatures: " + std::to_wstring(requirePlatformSecurityFeatures);
        if (requirePlatformSecurityFeatures == 1) {
            report += L" (Secure Boot uniquement)\r\n";
        } else if (requirePlatformSecurityFeatures == 3) {
            report += L" (Secure Boot + DMA Protection)\r\n";
        } else {
            report += L" (Non configuré)\r\n";
        }
    } else {
        report += L"\r\nConfiguration DeviceGuard non trouvée dans le registre.\r\n";
    }
}

void CheckVBSCredentialGuard() {
    SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Vérification VBS/Credential Guard...");
    LogMessage(L"Démarrage vérification VBS/Credential Guard");

    g_features.clear();
    ListView_DeleteAllItems(g_hwndListView);

    // Initialize COM
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        MessageBoxW(g_hwndMain, L"Échec initialisation COM", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

    // Create WMI connection
    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hr)) {
        MessageBoxW(g_hwndMain, L"Échec création WbemLocator", L"Erreur", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\Microsoft\\Windows\\DeviceGuard"), nullptr, nullptr, 0,
                             NULL, 0, 0, &pSvc);

    if (FAILED(hr)) {
        MessageBoxW(g_hwndMain,
                   L"Échec connexion WMI DeviceGuard\r\nWin32_DeviceGuard peut ne pas être disponible sur ce système",
                   L"Erreur", MB_OK | MB_ICONERROR);
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    // Query Win32_DeviceGuard
    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_DeviceGuard"),
                        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);

    if (FAILED(hr)) {
        MessageBoxW(g_hwndMain, L"Échec requête Win32_DeviceGuard", L"Erreur", MB_OK | MB_ICONERROR);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtProp;

        // VirtualizationBasedSecurityStatus
        hr = pclsObj->Get(L"VirtualizationBasedSecurityStatus", 0, &vtProp, 0, 0);
        DWORD vbsStatus = (SUCCEEDED(hr) && vtProp.vt == VT_I4) ? vtProp.intVal : 0;
        VariantClear(&vtProp);

        SecurityFeature vbsFeature;
        vbsFeature.feature = L"Virtualization-Based Security (VBS)";
        vbsFeature.state = GetStateString(vbsStatus);
        vbsFeature.prerequisites = L"UEFI, Secure Boot, DEP, IOMMU";
        vbsFeature.status = (vbsStatus == 2) ? L"Opérationnel" : L"Non opérationnel";
        vbsFeature.recommendations = (vbsStatus == 2) ? L"Maintenir activé" : L"Activer VBS si supporté";
        g_features.push_back(vbsFeature);

        // SecurityServicesRunning
        hr = pclsObj->Get(L"SecurityServicesRunning", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && (vtProp.vt & VT_ARRAY)) {
            SAFEARRAY* psa = vtProp.parray;
            LONG lLower, lUpper;
            SafeArrayGetLBound(psa, 1, &lLower);
            SafeArrayGetUBound(psa, 1, &lUpper);

            bool credentialGuardRunning = false;
            bool hvciRunning = false;

            for (LONG i = lLower; i <= lUpper; i++) {
                LONG index = i;
                VARIANT element;
                SafeArrayGetElement(psa, &index, &element);

                if (element.vt == VT_I4) {
                    DWORD service = element.intVal;
                    if (service & 1) credentialGuardRunning = true;  // Bit 1: Credential Guard
                    if (service & 2) hvciRunning = true;             // Bit 2: HVCI
                }
                VariantClear(&element);
            }

            // Credential Guard
            SecurityFeature cgFeature;
            cgFeature.feature = L"Credential Guard";
            cgFeature.state = credentialGuardRunning ? L"Activé et en cours d'exécution" : L"Non actif";
            cgFeature.prerequisites = L"VBS activé, TPM 2.0, Secure Boot";
            cgFeature.status = credentialGuardRunning ? L"Protège les identifiants" : L"Non protégé";
            cgFeature.recommendations = credentialGuardRunning ? L"Maintenir activé" : L"Activer pour protection identifiants";
            g_features.push_back(cgFeature);

            // HVCI (Hypervisor-protected Code Integrity)
            SecurityFeature hvciFeature;
            hvciFeature.feature = L"HVCI (Code Integrity)";
            hvciFeature.state = hvciRunning ? L"Activé et en cours d'exécution" : L"Non actif";
            hvciFeature.prerequisites = L"VBS activé, pilotes compatibles";
            hvciFeature.status = hvciRunning ? L"Intégrité du code protégée" : L"Non protégé";
            hvciFeature.recommendations = hvciRunning ? L"Maintenir activé" : L"Activer si pilotes compatibles";
            g_features.push_back(hvciFeature);
        }
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    // Check TPM
    bool tpmPresent = CheckTPMPresence();
    SecurityFeature tpmFeature;
    tpmFeature.feature = L"TPM (Trusted Platform Module)";
    tpmFeature.state = tpmPresent ? L"Présent et fonctionnel" : L"Non détecté";
    tpmFeature.prerequisites = L"TPM 2.0 matériel";
    tpmFeature.status = tpmPresent ? L"Disponible pour attestation" : L"Non disponible";
    tpmFeature.recommendations = tpmPresent ? L"OK" : L"Installer TPM 2.0 si possible";
    g_features.push_back(tpmFeature);

    // Populate ListView
    for (const auto& feature : g_features) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(g_hwndListView);
        lvi.pszText = (LPWSTR)feature.feature.c_str();
        int index = ListView_InsertItem(g_hwndListView, &lvi);

        ListView_SetItemText(g_hwndListView, index, 1, (LPWSTR)feature.state.c_str());
        ListView_SetItemText(g_hwndListView, index, 2, (LPWSTR)feature.prerequisites.c_str());
        ListView_SetItemText(g_hwndListView, index, 3, (LPWSTR)feature.status.c_str());
        ListView_SetItemText(g_hwndListView, index, 4, (LPWSTR)feature.recommendations.c_str());
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Vérification terminée");
    LogMessage(L"Vérification VBS/Credential Guard terminée");
}

void TestPrerequisites() {
    std::wstring report = L"=== TEST DES PRÉREQUIS ===\r\n\r\n";

    // Check Secure Boot
    DWORD secureBootEnabled = 0;
    DWORD size = sizeof(DWORD);
    GetFirmwareEnvironmentVariableW(L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
                                    &secureBootEnabled, size);
    report += L"Secure Boot: ";
    report += (GetLastError() != ERROR_INVALID_FUNCTION && secureBootEnabled) ? L"Activé\r\n" : L"Désactivé ou non supporté\r\n";

    // Check Virtualization
    SYSTEM_INFO si = {};
    GetNativeSystemInfo(&si);
    report += L"Architecture: ";
    report += (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? L"x64 (OK)\r\n" : L"Non supporté\r\n";

    // Check DEP
    DWORD depFlags = 0;
    BOOL permanent = FALSE;
    if (GetProcessDEPPolicy(GetCurrentProcess(), &depFlags, &permanent)) {
        report += L"DEP: Activé\r\n";
    } else {
        report += L"DEP: État inconnu\r\n";
    }

    // Check TPM
    bool tpmPresent = CheckTPMPresence();
    report += L"TPM 2.0: ";
    report += tpmPresent ? L"Présent\r\n" : L"Non détecté\r\n";

    // Check Registry
    CheckDeviceGuardRegistry(report);

    report += L"\r\n=== RECOMMANDATIONS ===\r\n";
    report += L"Pour activer VBS/Credential Guard:\r\n";
    report += L"1. Activer Secure Boot dans UEFI/BIOS\r\n";
    report += L"2. Activer virtualisation (VT-x/AMD-V) dans BIOS\r\n";
    report += L"3. Installer TPM 2.0 si absent\r\n";
    report += L"4. Configurer via GPO ou registre DeviceGuard\r\n";

    MessageBoxW(g_hwndMain, report.c_str(), L"Test Prérequis", MB_OK | MB_ICONINFORMATION);
    LogMessage(L"Test prérequis effectué");
}

void ExportReport() {
    wchar_t fileName[MAX_PATH] = L"CredentialGuardChecker_Report.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwndMain;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn)) {
        std::wofstream csvFile(fileName, std::ios::out | std::ios::binary);
        if (csvFile.is_open()) {
            // UTF-8 BOM
            csvFile.put(0xEF);
            csvFile.put(0xBB);
            csvFile.put(0xBF);

            csvFile << L"Fonctionnalité,État,Prérequis,Statut,Recommandations\n";

            int itemCount = ListView_GetItemCount(g_hwndListView);
            for (int i = 0; i < itemCount; i++) {
                wchar_t buffer[1024];

                ListView_GetItemText(g_hwndListView, i, 0, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 1, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 2, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 3, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 4, buffer, 1024);
                csvFile << L"\"" << buffer << L"\"\n";
            }

            csvFile.close();
            MessageBoxW(g_hwndMain, L"Export CSV réussi!", L"Succès", MB_OK | MB_ICONINFORMATION);
            LogMessage(L"Export CSV vers: " + std::wstring(fileName));
        }
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Buttons
            CreateWindowExW(0, L"BUTTON", L"Vérifier VBS/CG",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           10, 10, 150, 30, hwnd, (HMENU)1001, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Tester prérequis",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           170, 10, 150, 30, hwnd, (HMENU)1002, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Exporter rapport",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           330, 10, 150, 30, hwnd, (HMENU)1003, nullptr, nullptr);

            // ListView
            g_hwndListView = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                             WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
                                             10, 50, 980, 400, hwnd, (HMENU)1004, nullptr, nullptr);
            ListView_SetExtendedListViewStyle(g_hwndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMNW lvc = {};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;

            lvc.pszText = (LPWSTR)L"Fonctionnalité";
            lvc.cx = 200;
            ListView_InsertColumn(g_hwndListView, 0, &lvc);

            lvc.pszText = (LPWSTR)L"État";
            lvc.cx = 200;
            ListView_InsertColumn(g_hwndListView, 1, &lvc);

            lvc.pszText = (LPWSTR)L"Prérequis";
            lvc.cx = 200;
            ListView_InsertColumn(g_hwndListView, 2, &lvc);

            lvc.pszText = (LPWSTR)L"Statut";
            lvc.cx = 150;
            ListView_InsertColumn(g_hwndListView, 3, &lvc);

            lvc.pszText = (LPWSTR)L"Recommandations";
            lvc.cx = 200;
            ListView_InsertColumn(g_hwndListView, 4, &lvc);

            // StatusBar
            g_hwndStatus = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
                                          WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                          0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Prêt - Ayi NEDJIMI Consultants");

            LogMessage(L"CredentialGuardChecker démarré");
            break;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case 1001: // Vérifier VBS/CG
                    CheckVBSCredentialGuard();
                    break;

                case 1002: // Tester prérequis
                    TestPrerequisites();
                    break;

                case 1003: // Exporter
                    ExportReport();
                    break;
            }
            break;
        }

        case WM_SIZE: {
            RECT rect;
            GetClientRect(hwnd, &rect);

            SetWindowPos(g_hwndListView, nullptr, 10, 50, rect.right - 20, rect.bottom - 80, SWP_NOZORDER);
            SendMessageW(g_hwndStatus, WM_SIZE, 0, 0);
            break;
        }

        case WM_DESTROY:
            LogMessage(L"CredentialGuardChecker fermé");
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"CredentialGuardCheckerClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    g_hwndMain = CreateWindowExW(0, wc.lpszClassName,
                                 L"Credential Guard Checker - Ayi NEDJIMI Consultants",
                                 WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 1020, 520,
                                 nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hwndMain, nCmdShow);
    UpdateWindow(g_hwndMain);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
