// 仿真混淆样本：字符串数组 + 十六进制命名 + 宿主读取 + 循环异或 + 常量折叠写法
var _0x4f2a = ['userAgent', 'cookie', 'width', 'getItem', 'unused'];

function _0x1a2b(a, b) {
  var c = 0;
  for (var i = 0; i < a.length; i++) c = (c * 31 + a.charCodeAt(i)) >>> 0;
  return c ^ b;
}

function _0x3c4d(s) {
  var out = '';
  var key = [18, 52, 86];
  for (var i = 0; i < s.length; i++) out += String.fromCharCode(s.charCodeAt(i) ^ key[i % key.length]);
  return out;
}

function makeSign(payload) {
  var ua = navigator.userAgent;
  var w = screen.width;
  var ck = document.cookie;
  var raw = payload + '|' + ua + '|' + w + '|' + ck;
  var h = _0x1a2b(raw, 0x1f);
  return _0x3c4d(btoa(String(h)));
}

window.__sign = makeSign;
