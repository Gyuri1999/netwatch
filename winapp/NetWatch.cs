// NetWatch.exe για Windows — ο μικρός εκκινητής.
//
// Το ΜΟΝΟ που κάνει: ξεκινά την Python που βρίσκεται δίπλα του (python\pythonw.exe, υπογεγραμμένη από την Python
// Software Foundation) με το launcher.py. Δεν περιέχει συμπιεσμένο ή κρυμμένο κώδικα και δεν «ξεπακετάρει» τίποτα:
// όλος ο κώδικας της εφαρμογής είναι απλά αρχεία .py στον ίδιο φάκελο, που μπορεί να τα διαβάσει οποιοσδήποτε.
//
// Πριν ήταν εκτελέσιμο του PyInstaller: το ίδιο «κέλυφος» χρησιμοποιούν και πολλά κακόβουλα προγράμματα, και τα
// antivirus έβγαζαν ψευδείς συναγερμούς.
//
// Μεταγλώττιση (το κάνει το winapp\build.ps1, με τον csc.exe που έχουν όλα τα Windows 10/11):
//   csc /target:winexe /platform:x64 /optimize+ /codepage:65001 /win32icon:NetWatch.ico /out:NetWatch.exe NetWatch.cs AssemblyInfo.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    // Κανόνες των Windows για ορίσματα γραμμής εντολών (όπως τους διαβάζει η CommandLineToArgvW / η Python).
    static string Quote(string a)
    {
        if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
        var sb = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in a)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { sb.Append('\\', slashes * 2 + 1); sb.Append('"'); slashes = 0; continue; }
            sb.Append('\\', slashes); slashes = 0; sb.Append(c);
        }
        sb.Append('\\', slashes * 2);
        sb.Append('"');
        return sb.ToString();
    }

    [STAThread]
    static int Main(string[] args)
    {
        string dir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        string py = Path.Combine(dir, "python", "pythonw.exe");
        string script = Path.Combine(dir, "launcher.py");
        if (!File.Exists(py) || !File.Exists(script))
        {
            // Χωρίς την Python δεν μπορεί να τρέξει ούτε ο έλεγχος του launcher.py: το λέμε από εδώ.
            bool inZip = dir.IndexOf(".zip", StringComparison.OrdinalIgnoreCase) >= 0;
            string why = inZip
                ? "Φαίνεται ότι το άνοιξες μέσα από το αρχείο .zip.\nΚάνε πρώτα δεξί κλικ στο zip → «Εξαγωγή όλων…» και άνοιξε το NetWatch.exe από τον φάκελο που θα δημιουργηθεί."
                : "Συνήθως φταίει ένα antivirus που έσβησε ή έβαλε σε καραντίνα αρχεία της εφαρμογής.\nΤα αρχεία μένουν σβησμένα ακόμα κι αν μετά απενεργοποιήσεις το antivirus.\n\nΤι να κάνεις:\n1. Στο antivirus, βάλε εξαίρεση για αυτόν τον φάκελο.\n2. Σβήσε τον φάκελο και αποσυμπίεσε ξανά το zip.\n3. Άνοιξε ξανά το NetWatch.exe.";
            string missing = (File.Exists(py) ? "" : "  • python\\pythonw.exe\n") + (File.Exists(script) ? "" : "  • launcher.py\n");
            if (Array.IndexOf(args, "--preflight") < 0 && Array.IndexOf(args, "--selftest") < 0)
                MessageBoxW(IntPtr.Zero, "Το NetWatch δεν μπορεί να ξεκινήσει: λείπουν αρχεία του.\n\n" + why + "\n\nΛείπουν:\n" + missing + "\nΦάκελος: " + dir,
                            "NetWatch — δεν ξεκινά", 0x30);
            return 1;
        }
        var sb = new StringBuilder("-X utf8 " + Quote(script));
        foreach (string a in args) sb.Append(' ').Append(Quote(a));
        var psi = new ProcessStartInfo(py, sb.ToString()) { UseShellExecute = false, WorkingDirectory = dir };
        psi.EnvironmentVariables["NETWATCH_BUNDLE"] = dir;      // ο launcher.py μαθαίνει πού είναι ο φάκελος της εφαρμογής
        psi.EnvironmentVariables["PYTHONUTF8"] = "1";
        psi.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1";
        try
        {
            using (Process p = Process.Start(psi))
            {
                if (args.Length == 0) return 0;                  // κανονική εκκίνηση: η εφαρμογή συνεχίζει μόνη της
                p.WaitForExit();                                 // --selftest / --preflight: γυρνάμε τον κωδικό εξόδου
                return p.ExitCode;
            }
        }
        catch (Exception e)
        {
            MessageBoxW(IntPtr.Zero, "Το NetWatch δεν μπόρεσε να ξεκινήσει την Python:\n\n" + e.Message + "\n\n" + py, "NetWatch — σφάλμα", 0x10);
            return 1;
        }
    }
}
