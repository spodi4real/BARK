# Testing BARK on two computers

This is the first time BARK runs on two separate computers. Follow the steps in
order. Every step says exactly what to click. Where something can go wrong, the
step says what you will see and what to do.

**Names used below**

* **LAPTOP** — this development laptop. It will *control* the other computer.
* **PC2** — the second computer. It will be the **BARK server** and the computer
  being controlled. (The laptop must not be the server: it is not always on.)

Both computers should be on the **same network** (same office or home router)
for the first test. Testing across the internet comes after this works.

Time needed: about 20 minutes.

---

## Part A — Put BARK on a USB stick (on the LAPTOP)

1. Open File Explorer.
2. Go to `C:\Users\MiQDAD\Desktop\BARK\target\release`
3. Right-click **BARK.exe** → **Copy**.
4. Open your USB stick in File Explorer → right-click an empty area → **Paste**.

BARK.exe is a single file (about 6 MB). Nothing else is needed; it does not
need the Visual C++ runtime or anything else installed.

---

## Part B — Set up PC2 as the BARK server

1. On PC2, plug in the USB stick.
2. In File Explorer, open `C:\` → right-click an empty area → **New** →
   **Folder** → name it `BARK`.
3. Copy **BARK.exe** from the USB stick into `C:\BARK`.
4. Double-click `C:\BARK\BARK.exe`.
   * If a blue box says **"Windows protected your PC"**: click **More info**,
     then **Run anyway**. (BARK is not yet digitally signed; that comes with
     the installer.)
5. The BARK window opens. The status bar at the bottom says the server is
   **NOT SET UP**. That is expected.
6. Menu **Tools** → **Settings...**
7. Tick **This computer is the BARK server**. The box **Relay connections for
   other BARK devices** ticks itself — leave it ticked.
8. Optional: type a name in **Device name**, for example `PC2`.
9. Click **OK**.
10. A **Windows Security Alert** about BARK may appear. Tick **both** boxes
    (Private networks and Public networks) if both are shown, then click
    **Allow access**. If Windows asks for an administrator password, give it.
    * No alert appeared? Open **Tools** → **Settings...** → click **Allow in
      Windows Firewall...** → click **Yes** on the Windows prompt → **OK**.
11. The status bar should now say **Server: ONLINE**.
12. Open **Tools** → **Settings...** again. The box in the middle now shows:

        Server address:  192.168.x.x:57411
        Server key:  XXXX-XXXX-...

13. Click **Copy**, then **OK** on the message.
14. Open **Notepad** (Start menu → type `notepad` → Enter), press **Ctrl+V**,
    and save the file to the USB stick as `join.txt`.
15. Click **Cancel** to close Settings.

---

## Part C — Connect the LAPTOP to the server

1. On the LAPTOP, double-click `C:\Users\MiQDAD\Desktop\BARK\target\release\BARK.exe`
   (not the BARK-DEMO file — that is the one-computer demo).
2. Plug in the USB stick, open `join.txt` in Notepad, press **Ctrl+A**, then
   **Ctrl+C**.
3. In BARK: **Tools** → **Settings...** → click **Paste**. The server address
   and key fill in. Click **OK**.
4. Within a few seconds the status bar says **Server: ONLINE** with a number of
   milliseconds.
   * Still **OFFLINE**? Read the message in the **This Computer** box. The
     usual causes: PC2's firewall (repeat Part B step 10), or the two
     computers are on different networks. Open **Tools** → **Diagnostics...**
     for details.

---

## Part D — Pair the two computers (done once, ever)

1. On **PC2**: click **Show Pairing Code...** A window shows PC2's
   **Device ID** (like `BA-4K7P-2WQX`) and a six-character **code**.
2. On the **LAPTOP**: **File** → **Add Device...**
3. Type PC2's Device ID and the code. Click **Pair**.
4. The LAPTOP says **"Paired with PC2"**. PC2 appears in the Favorites list as
   **ONLINE**, Access **You control it**.
5. On PC2, close the pairing-code window.

---

## Part E — Control PC2 from the LAPTOP

1. On the LAPTOP, double-click **PC2** in the Favorites list.
2. A session window opens with PC2's screen in it. On **PC2**, a yellow bar
   appears at the top: **"LAPTOP is controlling this computer"** with an
   **End Session** button.
3. Try these on the LAPTOP, inside the session window:
   * Move the mouse and click the Start button of PC2.
   * Open Notepad on PC2 and type a sentence.
   * Scroll a web page on PC2.
   * Menu **Actions** → **Send Windows Key**.
4. **Write down the numbers** in the session window's status bar (or press
   **Win+Shift+S** to take a screenshot):
   * `DIRECT (LAN)` or `RELAYED`
   * `RTT ... ms`
   * `... fps  ... Mbit/s`
   * `Remote ... ms  Decode ... ms  Input→frame ... ms`
   * The last box: `H.264, GPU decode` or `CPU decode`

   **Input→frame** is the most important number: the time from pressing a key
   on the laptop to that key's result appearing in the picture. It appears
   after you type or click something that changes PC2's screen.
5. Security check: in the session window, **Session** → **Connection
   Information...** shows **verification words**. On PC2, the BARK window's
   status bar shows words too. They must be identical.
6. End the session in either way:
   * On the LAPTOP: close the session window.
   * On PC2: click **End Session** in the yellow bar.

---

## Part F — Things that are expected NOT to work yet

Do not report these as bugs; they are known and listed as not built:

* **Task Manager, installers, or any "Run as administrator" window on PC2**
  cannot be clicked or typed into. Windows blocks input to them from a normal
  program; the installed BARK service will fix this.
* **The sign-in screen, the lock screen, Ctrl+Alt+Del** — need the BARK
  service, not built yet. If PC2 locks, the picture pauses and says why.
* **Windows key / Alt+Tab pressed on the laptop keyboard** stay on the laptop.
  Use the **Actions** menu to send them.
* **Only PC2's first monitor** is shown.
* **Clipboard and file transfer** — not built.
* **Closing the BARK window** hides it next to the clock; BARK keeps running so
  the computer stays reachable. To really quit: **File** → **Exit**.

---

## Part G — Optional: test the relay

This forces the connection through PC2's relay instead of directly, to prove
the fallback works on a real network.

1. On the LAPTOP, in BARK: **File** → **Exit**.
2. Press **Win+R**, type the line below exactly, press **Enter**:

        notepad %LOCALAPPDATA%\BARK\profiles\default\config.json

3. After the first `{` add a new line with exactly:

        "force_relay": true,

4. **File** → **Save**, close Notepad, start BARK again, and connect to PC2.
   The session window should say **RELAYED**. Write down the numbers again.
5. Undo it afterwards: remove that line, save, restart BARK.

---

## What to send back

1. The numbers from Part E step 4 (and Part G if you did it).
2. Anything that did not work, with the exact message shown.
3. If something failed: on the computer that failed, **Tools** →
   **Diagnostics...** → **Copy to Clipboard**, and paste that text.
4. Logs, if asked: **Tools** → **Open Log Folder**.
