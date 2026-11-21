# Screenshot Guide — Windows Service Enumeration

All eight screenshots in this repository were extracted directly from the original **Enumeration Lab A.cox.docx** report. Filenames were changed for readability, but screenshot contents have not been edited. `image1.jpg` is the university logo and is intentionally excluded as nontechnical evidence.

| Figure | Original embedded image | GitHub filename | Verified content | README placement |
| --- | --- | --- | --- | --- |
| 1 | `image2.png` | `screenshots/01-windows-services-console.png` | Services.msc showing Windows services, running states, start types, and service identities | Step 1: Services GUI |
| 2 | `image3.png` | `screenshots/02-powershell-running-services.png` | PowerShell Get-Service filtered to currently running services | Step 2: PowerShell service enumeration |
| 3 | `image5.png` | `screenshots/03-netstat-listening-ports.png` | netstat -ano display showing local TCP endpoints, connection state and PIDs | Step 3: Listening ports |
| 4 | `image4.png` | `screenshots/04-tasklist-pid-mapping.png` | tasklist /FI commands mapping five selected PIDs to executable names | Step 4: Process attribution |
| 5 | `image6.png` | `screenshots/05-installed-software-versions.png` | Programs and Features showing Chrome 145.0.7632.118, .NET Runtime 6.0.16, and Epic Online Services 4.1.0 | Step 5: Installed software inventory |
| 6 | `image7.png` | `screenshots/06-cve-2023-24897-nvd.png` | NVD details for CVE-2023-24897 affecting .NET and Visual Studio products | Step 6: CVE research - .NET |
| 7 | `image8.png` | `screenshots/07-cve-2026-2441-nvd.png` | NVD details for Chrome CSS use-after-free vulnerability CVE-2026-2441 | Step 6: CVE research - Chrome |
| 8 | `image9.png` | `screenshots/08-cve-2021-47739-nvd.png` | NVD details for Easy Anti-Cheat unquoted service path CVE-2021-47739 | Step 6: CVE research - Easy Anti-Cheat |

## Evidence Notes

- The screenshots are **point-in-time** and should not be presented as live/current system status.
- The NVD record screenshots document vulnerability **research**, not proof of exploitability.
- The programs list shows **Chrome 145.0.7632.118**, while the narrative mentions `145.0.7632.45`; the README explicitly discloses the difference.
- The programs list shows **Epic Online Services 4.1.0**; it does not establish that **Easy Anti-Cheat 4.0** was installed.
- The original report table lists five selected TCP listener/PID examples, not every port in the `netstat` screenshot.
