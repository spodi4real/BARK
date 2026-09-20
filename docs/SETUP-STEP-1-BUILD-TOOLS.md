# Setup Step 1 — Install the Microsoft C++ Build Tools

You only ever do this **once**, on this laptop. It is not needed on the server or
on any computer that will just *run* BARK. It is only needed on the machine that
*builds* BARK.

Rust is already installed. It needs Microsoft's linker and the Windows SDK to
produce a Windows program, and Microsoft only ships those through their own
installer, which needs Administrator rights.

---

## What you need to do

### 1. Open an Administrator PowerShell window

* Press the **Windows key** on your keyboard.
* Type: `powershell`
* You will see **Windows PowerShell** at the top of the list.
* **Right-click** it, and choose **Run as administrator**.
* Windows will show a blue box asking *"Do you want to allow this app to make
  changes to your device?"* — click **Yes**.

You should now have a window with a dark blue or black background, and a line
that ends in `>` waiting for you to type. The title bar will say
**Administrator: Windows PowerShell**.

If the title bar does **not** say "Administrator", close it and do this step
again — the command below will fail without it.

### 2. Copy this command

Select the whole line below and copy it (Ctrl+C):

```
winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --accept-source-agreements --accept-package-agreements --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

### 3. Paste it into the PowerShell window

* Click once inside the PowerShell window.
* Press **Ctrl+V** to paste. (If Ctrl+V does nothing, **right-click** instead —
  in PowerShell, right-click pastes.)
* Press **Enter**.

### 4. Wait

This downloads roughly **4–7 GB** and takes **10 to 40 minutes** depending on
your internet connection.

While it runs you will see very little. It may look frozen. It is not frozen —
the `--quiet` option means Microsoft's installer does its work without opening
its own window. Leave it alone.

**Do not close the window.** **Do not press Ctrl+C.**

### 5. What you should see when it finishes

The window will print something like:

```
Successfully installed
```

and give you a fresh `>` prompt to type at.

---

## If something goes wrong

**"winget is not recognized"**
Your Windows does not have the App Installer. Open the Microsoft Store, search
for **App Installer**, and install it. Then start again from step 1.

**"Installer failed with exit code: 1602"**
The installation was cancelled. Usually this means the UAC prompt was dismissed.
Start again from step 1 and click **Yes** on the blue box.

**"Installer failed with exit code: 3010"**
This one is *success*. It means Windows wants a restart. Restart the computer
and carry on.

**"Access is denied" or "requires elevation"**
The PowerShell window is not running as Administrator. Close it and redo step 1,
making sure you choose **Run as administrator**.

**It downloads for a long time and then fails with a network error**
Run the exact same command again. The installer resumes rather than starting
over.

---

## How we confirm it worked

Tell me it has finished and I will check it from here. The check looks for the
Microsoft linker (`link.exe`) and the Windows SDK, and then compiles a small
test program to prove the whole chain works end to end.

You do not need to verify anything yourself.
