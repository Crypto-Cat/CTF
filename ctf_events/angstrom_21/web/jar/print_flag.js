var divs = document.getElementsByTagName('div')
var flag = ""

for (var i = 0; i < divs.length; i++){
  flag += divs[i].innerText
}

console.log(flag)