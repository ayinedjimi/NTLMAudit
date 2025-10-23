/*******************************************************************************
 * NTLMAudit - Outil d'audit des événements NTLM
 *
 * Auteur: Ayi NEDJIMI
 * Copyright (c) 2025 Ayi NEDJIMI
 *
 * Description:
 *   Extrait et analyse les événements de sécurité Windows liés à l'authentification
 *   NTLM. Permet d'identifier les endpoints utilisant NTLM et de détecter les
 *   tentatives d'authentification suspectes.
 *
 * Fonctionnalités:
 *   - Extraction des événements Security log (Event ID 4624)
 *   - Filtrage des authentications NTLM (LogonType 3)
 *   - Agrégation par client/service
 *   - Export CSV UTF-8
 *   - Logging détaillé
 *
 * Compilation:
 *   cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE NTLMAudit.cpp ^
 *   /Fe:NTLMAudit.exe /link user32.lib comctl32.lib wevtapi.lib
 *
 * Licence: MIT
 ******************************************************************************/

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <winevt.h>
#include <thread>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <mutex>
#include <map>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "user32.lib")

// Template RAII pour handles
template<typename T, typename Deleter>
class AutoHandle {
    T handle;
    Deleter deleter;
public:
    AutoHandle(T h, Deleter d) : handle(h), deleter(d) {}
    ~AutoHandle() { if (handle) deleter(handle); }
    T get() const { return handle; }
    operator bool() const { return handle != nullptr && handle != INVALID_HANDLE_VALUE; }
    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;
};

// Globals
HWND g_hMainWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hStatusBar = nullptr;
HWND g_hBtnScan = nullptr;
HWND g_hBtnExport = nullptr;
HWND g_hEditDays = nullptr;
std::mutex g_mutex;
bool g_scanning = false;
std::wstring g_logPath;

// Structure pour événement NTLM
struct NTLMEvent {
    std::wstring timestamp;
    std::wstring clientIP;
    std::wstring clientName;
    std::wstring targetUser;
    std::wstring serviceName;
    DWORD eventID;
};

std::vector<NTLMEvent> g_events;

// Logging
void LogMessage(const std::wstring& msg) {
    std::wofstream log(g_logPath, std::ios::app);
    if (log.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timestamp[64];
        swprintf_s(timestamp, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        log << timestamp << msg << std::endl;
    }
}

// Initialiser ListView
void InitListView() {
    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.pszText = const_cast<LPWSTR>(L"Horodatage");
    lvc.cx = 150;
    lvc.iSubItem = 0;
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"IP Client");
    lvc.cx = 120;
    lvc.iSubItem = 1;
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Nom Client");
    lvc.cx = 150;
    lvc.iSubItem = 2;
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Utilisateur");
    lvc.cx = 150;
    lvc.iSubItem = 3;
    ListView_InsertColumn(g_hListView, 3, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Service");
    lvc.cx = 120;
    lvc.iSubItem = 4;
    ListView_InsertColumn(g_hListView, 4, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Event ID");
    lvc.cx = 80;
    lvc.iSubItem = 5;
    ListView_InsertColumn(g_hListView, 5, &lvc);
}

// Extraire valeur d'un événement
std::wstring GetEventProperty(EVT_HANDLE hEvent, LPCWSTR propertyPath) {
    EVT_HANDLE hContext = EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
    if (!hContext) return L"";

    AutoHandle<EVT_HANDLE, decltype(&EvtClose)> autoContext(hContext, EvtClose);

    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    EvtRender(hContext, hEvent, EvtRenderEventValues, 0, nullptr, &bufferUsed, &propertyCount);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return L"";

    std::vector<BYTE> buffer(bufferUsed);
    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
        return L"";
    }

    PEVT_VARIANT pRenderedValues = reinterpret_cast<PEVT_VARIANT>(buffer.data());

    // Pour Event 4624: System properties
    // TimeCreated = index 7
    if (propertyCount > 7 && pRenderedValues[7].Type == EvtVarTypeFileTime) {
        FILETIME ft = *(FILETIME*)&pRenderedValues[7].FileTimeVal;
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);
        wchar_t timeStr[64];
        swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return timeStr;
    }

    return L"";
}

// Extraire données XML de l'événement
std::wstring GetEventXML(EVT_HANDLE hEvent) {
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return L"";

    std::vector<WCHAR> buffer(bufferUsed / sizeof(WCHAR));
    if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
        return L"";
    }

    return std::wstring(buffer.data());
}

// Parser simple XML pour extraire valeur
std::wstring ExtractXMLValue(const std::wstring& xml, const std::wstring& tagName) {
    std::wstring openTag = L"<" + tagName + L">";
    std::wstring closeTag = L"</" + tagName + L">";

    size_t start = xml.find(openTag);
    if (start == std::wstring::npos) return L"";

    start += openTag.length();
    size_t end = xml.find(closeTag, start);
    if (end == std::wstring::npos) return L"";

    return xml.substr(start, end - start);
}

// Scanner les événements NTLM
void ScanNTLMEvents(int days) {
    LogMessage(L"Début du scan NTLM pour les " + std::to_wstring(days) + L" derniers jours");
    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Scan des événements NTLM en cours...");

    // Construire requête XPath pour Event 4624 (Logon) avec LogonType 3
    std::wstring query = L"*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='3']]";

    // Ouvrir le canal Security
    EVT_HANDLE hResults = EvtQuery(nullptr, L"Security", query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) {
        DWORD err = GetLastError();
        LogMessage(L"Erreur EvtQuery: " + std::to_wstring(err));
        SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Erreur: Impossible d'ouvrir le journal Security");
        return;
    }

    AutoHandle<EVT_HANDLE, decltype(&EvtClose)> autoResults(hResults, EvtClose);

    std::vector<NTLMEvent> events;
    DWORD returned = 0;
    EVT_HANDLE hEvent = nullptr;
    int count = 0;

    // Calculer timestamp limite
    FILETIME ftNow, ftLimit;
    GetSystemTimeAsFileTime(&ftNow);
    ULARGE_INTEGER ul;
    ul.LowPart = ftNow.dwLowDateTime;
    ul.HighPart = ftNow.dwHighDateTime;
    ul.QuadPart -= static_cast<ULONGLONG>(days) * 24 * 60 * 60 * 10000000ULL;
    ftLimit.dwLowDateTime = ul.LowPart;
    ftLimit.dwHighDateTime = ul.HighPart;

    while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned) && returned > 0) {
        AutoHandle<EVT_HANDLE, decltype(&EvtClose)> autoEvent(hEvent, EvtClose);

        // Obtenir XML de l'événement
        std::wstring xml = GetEventXML(hEvent);
        if (xml.empty()) continue;

        // Vérifier si c'est NTLM
        std::wstring authPackage = ExtractXMLValue(xml, L"Data[@Name='AuthenticationPackageName']");
        if (authPackage.find(L"NTLM") == std::wstring::npos) continue;

        NTLMEvent evt;
        evt.eventID = 4624;
        evt.timestamp = GetEventProperty(hEvent, L"TimeCreated");
        evt.clientIP = ExtractXMLValue(xml, L"Data[@Name='IpAddress']");
        evt.clientName = ExtractXMLValue(xml, L"Data[@Name='WorkstationName']");
        evt.targetUser = ExtractXMLValue(xml, L"Data[@Name='TargetUserName']");
        evt.serviceName = ExtractXMLValue(xml, L"Data[@Name='LogonProcessName']");

        if (evt.clientIP.empty()) evt.clientIP = L"-";
        if (evt.clientName.empty()) evt.clientName = L"-";
        if (evt.targetUser.empty()) evt.targetUser = L"-";
        if (evt.serviceName.empty()) evt.serviceName = L"-";

        events.push_back(evt);
        count++;

        if (count % 100 == 0) {
            std::wstring status = L"Événements trouvés: " + std::to_wstring(count);
            SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)status.c_str());
        }
    }

    // Mettre à jour UI
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_events = events;
    }

    PostMessage(g_hMainWnd, WM_USER + 1, 0, 0);
    LogMessage(L"Scan terminé: " + std::to_wstring(count) + L" événements NTLM trouvés");
}

// Mettre à jour ListView
void UpdateListView() {
    ListView_DeleteAllItems(g_hListView);

    std::lock_guard<std::mutex> lock(g_mutex);

    for (size_t i = 0; i < g_events.size(); i++) {
        const auto& evt = g_events[i];

        LVITEMW lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(evt.timestamp.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, i, 1, const_cast<LPWSTR>(evt.clientIP.c_str()));
        ListView_SetItemText(g_hListView, i, 2, const_cast<LPWSTR>(evt.clientName.c_str()));
        ListView_SetItemText(g_hListView, i, 3, const_cast<LPWSTR>(evt.targetUser.c_str()));
        ListView_SetItemText(g_hListView, i, 4, const_cast<LPWSTR>(evt.serviceName.c_str()));

        std::wstring eventIDStr = std::to_wstring(evt.eventID);
        ListView_SetItemText(g_hListView, i, 5, const_cast<LPWSTR>(eventIDStr.c_str()));
    }

    std::wstring status = L"Terminé: " + std::to_wstring(g_events.size()) + L" événements NTLM affichés";
    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)status.c_str());
}

// Exporter en CSV UTF-8
void ExportToCSV() {
    wchar_t fileName[MAX_PATH] = L"NTLMAudit_Export.csv";

    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    std::lock_guard<std::mutex> lock(g_mutex);

    std::wofstream csv(fileName);
    if (!csv.is_open()) {
        MessageBoxW(g_hMainWnd, L"Erreur lors de la création du fichier CSV", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    csv << L"\uFEFF";
    csv << L"Horodatage,IP Client,Nom Client,Utilisateur,Service,Event ID\n";

    for (const auto& evt : g_events) {
        csv << evt.timestamp << L","
            << evt.clientIP << L","
            << evt.clientName << L","
            << evt.targetUser << L","
            << evt.serviceName << L","
            << evt.eventID << L"\n";
    }

    csv.close();
    LogMessage(L"Export CSV: " + std::wstring(fileName));
    MessageBoxW(g_hMainWnd, L"Export CSV réussi!", L"Succès", MB_OK | MB_ICONINFORMATION);
}

// Gestionnaire de messages
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
    {
        // Titre
        CreateWindowExW(0, L"STATIC", L"NTLMAudit - Audit des événements NTLM",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            10, 10, 760, 25, hWnd, nullptr, nullptr, nullptr);

        // Contrôles
        CreateWindowExW(0, L"STATIC", L"Nombre de jours à analyser:",
            WS_CHILD | WS_VISIBLE,
            10, 45, 180, 20, hWnd, nullptr, nullptr, nullptr);

        g_hEditDays = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"7",
            WS_CHILD | WS_VISIBLE | ES_NUMBER,
            200, 43, 60, 22, hWnd, nullptr, nullptr, nullptr);

        g_hBtnScan = CreateWindowExW(0, L"BUTTON", L"Scanner",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            270, 42, 100, 24, hWnd, (HMENU)1, nullptr, nullptr);

        g_hBtnExport = CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            380, 42, 120, 24, hWnd, (HMENU)2, nullptr, nullptr);

        // ListView
        g_hListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            10, 75, 760, 400, hWnd, nullptr, nullptr, nullptr);
        ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        InitListView();

        // Barre de statut
        g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, L"",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hWnd, nullptr, nullptr, nullptr);
        SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Prêt");

        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) { // Scanner
            if (g_scanning) {
                MessageBoxW(hWnd, L"Un scan est déjà en cours", L"Information", MB_OK | MB_ICONINFORMATION);
                break;
            }

            wchar_t buffer[16];
            GetWindowTextW(g_hEditDays, buffer, 16);
            int days = _wtoi(buffer);
            if (days <= 0 || days > 365) {
                MessageBoxW(hWnd, L"Veuillez entrer un nombre de jours valide (1-365)", L"Erreur", MB_OK | MB_ICONERROR);
                break;
            }

            g_scanning = true;
            EnableWindow(g_hBtnScan, FALSE);
            std::thread([days]() {
                ScanNTLMEvents(days);
                g_scanning = false;
                EnableWindow(g_hBtnScan, TRUE);
            }).detach();
        }
        else if (LOWORD(wParam) == 2) { // Exporter
            ExportToCSV();
        }
        break;

    case WM_USER + 1:
        UpdateListView();
        break;

    case WM_SIZE:
        SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialiser log
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    g_logPath = std::wstring(tempPath) + L"WinTools_NTLMAudit_log.txt";
    LogMessage(L"=== NTLMAudit démarré ===");

    // Initialiser Common Controls
    INITCOMMONCONTROLSEX icc = { 0 };
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    // Enregistrer classe de fenêtre
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"NTLMAuditClass";
    RegisterClassExW(&wc);

    // Créer fenêtre
    g_hMainWnd = CreateWindowExW(0, L"NTLMAuditClass", L"NTLMAudit - Par Ayi NEDJIMI",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 560,
        nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    // Boucle de messages
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    LogMessage(L"=== NTLMAudit arrêté ===");
    return static_cast<int>(msg.wParam);
}
