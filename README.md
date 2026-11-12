# USB File Safety Checker

The app has two distinct checks:

1. **Filename review** runs in the browser. It flags some executable/script extensions, `autorun.inf`, and archives that it cannot inspect. This is a lightweight warning, not antivirus.
2. **Microsoft Defender drive scan** is available through the Windows-only local companion. It asks the installed Microsoft Defender command-line scanner to scan a selected, mounted drive.

## Run a real Windows Defender scan

The public GitHub Pages website cannot access your computer's drives or start Windows programs. To use the local Defender integration:

1. Download this repository using **Code → Download ZIP** on GitHub and extract the ZIP on your Windows computer. Or clone the repository if Git is installed.
2. Make sure Microsoft Defender Antivirus is active and the removable drive is connected.
3. Double-click `start-scanner.bat`. Python 3 must be installed; the app adds no third-party packages.
4. A browser opens at `http://127.0.0.1:8765/`. Select the USB drive (do not select a drive unless you know it is the one you want), then click **Scan drive** and confirm.
5. Keep the page and the command window open until the scan finishes. Close the command window with **Ctrl+C** when done.
6. If Defender reports detections, review **Windows Security → Virus & threat protection → Protection history**. This app deliberately disables automatic remediation; it does not quarantine or delete detected files for you.

The companion binds to `127.0.0.1` only, excludes the Windows system drive, and accepts scan requests only from its own local web page. It sends a drive-letter request to Defender; it does not upload files or send data to a scanning service. The scan itself is performed by Microsoft Defender on the computer. Fixed drives other than the system drive may appear in the list, so check the drive letter carefully before scanning.

## What the results mean

- **Defender reported no detections** means the installed Defender engine reported none for that scan. It is not a guarantee that a drive or file is safe. Keep protection enabled and signatures up to date.
- **Detections reported** means Defender lists one or more threats associated with that drive. Use Windows Security's Protection history to see details and choose an action.
- If Defender is disabled, its scan command is unavailable, the drive disconnects, or Defender cannot confirm its results, the app reports that instead of calling the drive clean.
- The filename review is separate from the Defender scan. Its **No obvious flags** status is never a malware verdict.

The scan command disables automatic remediation, so this app will not ask Defender to quarantine or delete scan detections. Windows real-time protection continues to operate according to your normal Windows Security settings and may take its own action. The local companion requires Windows and Microsoft Defender. It uses Python's standard library and built-in Windows Defender tools; there is no API key or third-party scanning dependency.

## Publish on GitHub Pages

GitHub Pages hosts the static `index.html`, so the filename review works there. For actual Defender scanning, download the source and run the local companion as described above; a hosted web page cannot directly access local drives.
