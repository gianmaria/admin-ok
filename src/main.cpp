#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <lm.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Secur32.lib")

using std::cout;
using std::wcout;
using std::endl;
using std::wstring;
using std::chrono::seconds;
using std::this_thread::sleep_for;

wstring date_time()
{
    // Get the current system time
    auto now = std::chrono::system_clock::now();

    // Convert the system time to a time_t type
    std::time_t current_time_t = std::chrono::system_clock::to_time_t(now);

    // Convert the time_t to a struct tm (for easy date and time extraction)
    struct tm buf{};
    auto err = localtime_s(&buf, &current_time_t);

    if (err != 0)
    {
        return L"";
    }

    // Format the date and time
    std::wstringstream formattedTime;
    formattedTime << std::put_time(&buf, L"%Y-%m-%d %H:%M:%S");

    return formattedTime.str();
}

wstring error_to_string(DWORD error)
{
    LPVOID errorMessage;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK;
    DWORD result = FormatMessage(
        flags,
        NULL,
        error,
        0,
        (LPWSTR)&errorMessage,
        0,
        NULL
    );

    if (result == 0)
    {
        DWORD formatMessageError = GetLastError();
        cout << "WARNING: FormatMessage failed with error code " << formatMessageError << endl;
        return L"";
    }

    wstring error_msg = wstring((LPWSTR)errorMessage);
    LocalFree(errorMessage);
    return error_msg;
}

wstring get_username_with_domain()
{
    wchar_t username[256]; // Buffer to hold the username
    DWORD username_size = sizeof(username) / sizeof(username[0]);

    EXTENDED_NAME_FORMAT name_format = NameSamCompatible;

    if (not GetUserNameExW(name_format, username, &username_size))
    {
        DWORD error = GetLastError();
        cout << "ERROR: GetUserName failed with error code " << error << std::endl;
        wcout << "  " << error_to_string(error) << endl;

        return L"";
    }

    return wstring(username);
}

std::vector<wstring> get_members_for_local_group(const wstring& local_group)
{
    std::vector<wstring> users;

    const WCHAR* server_name = NULL;
    const WCHAR* localgroup_name = local_group.c_str();
    DWORD level = 2;
    LOCALGROUP_MEMBERS_INFO_2* info;
    DWORD entries_read = 0;
    DWORD total_entries = 0;

    auto error = NetLocalGroupGetMembers(
        server_name,
        localgroup_name,
        level,
        reinterpret_cast<LPBYTE*>(&info),
        MAX_PREFERRED_LENGTH,
        &entries_read,
        &total_entries,
        NULL
    );

    if (error != NERR_Success)
    {
        wcout << L"ERROR: NetLocalGroupGetMembers failed with code: " << error << endl;
        wcout << "  " << error_to_string(error) << endl;
        return users;
    }

    if (info == NULL)
    {
        cout << "ERROR: no group found" << endl;
        return users;
    }

    if (entries_read != total_entries)
    {
        cout << "WARNING: not all entries have been enumerated" << endl;
    }

    for (DWORD i = 0;
         i < entries_read;
         ++i)
    {
        if (info[i].lgrmi2_sidusage == SidTypeUser)
        {
            users.emplace_back(info[i].lgrmi2_domainandname);
        }
    }

    if (info)
    {
        NetApiBufferFree(info);
    }

    return users;
}

bool add_account_to_group(const wstring& domain_and_name, const wstring& group)
{
    CONST WCHAR* servername = NULL;
    DWORD level = 3; // Specifies the domain and name of the new local group member
    DWORD total_entries = 1;

    LOCALGROUP_MEMBERS_INFO_3 info{};
    // TODO: spooky shit, cast to non const LPWSTR
    info.lgrmi3_domainandname = const_cast<LPWSTR>(domain_and_name.c_str());

    auto error = NetLocalGroupAddMembers(
        servername,
        group.c_str(),
        level,
        reinterpret_cast<LPBYTE>(&info),
        total_entries
    );

    if (error != NERR_Success)
    {
        wcout << L"ERROR: NetLocalGroupAddMembers failed with code: " << error << endl;
        wcout << "  " << error_to_string(error) << endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t *argv[])
{
    try
    {
        if (argc != 3)
        {
            wcout << "ERROR: not enough arguments" << endl
                << "monitors whether the user is in the selected group or not" << endl
                << "using: " << argv[0] << " <DOMAIN\\user> <GroupName>" << endl;
            return 1;
        }

        const auto account = wstring(argv[1]);
        const auto group = wstring(argv[2]);
        size_t sleep = 30; // sleep in seconds

        auto username = get_username_with_domain();
        wcout << date_time() << " INFO: you are (" << username << ")" << endl;

        for (;;)
        {
            auto users = get_members_for_local_group(group);

            if (users.size() == 0)
            {
                // something went wrong
                return 1;
            }

            //for (const auto& user : users)
            //{
            //    wcout << user << endl;
            //}

            auto it = std::find(users.begin(), users.end(), account);

            if (it == users.end())
            {
                // account is not part of the specified group!

                if (auto added = add_account_to_group(account, group);
                    added)
                {
                    wcout << date_time() << "(" << username << ") account " << account << " added to group " << group << endl;
                }
                else
                {
                    wcout << date_time() << "(" << username << ") " << "failed to add account " << account << " to group " << group << endl;
                }
            }
            else
            {
                //wcout << date_time() << " (" << username << ") okega" << endl;
            }

            sleep_for(seconds(sleep));
        }

        return 0;
    }
    catch(const std::exception& e)
    {
        cout << "EXCEPTION: " << e.what() << endl;
    }
    
    return 1;
}


