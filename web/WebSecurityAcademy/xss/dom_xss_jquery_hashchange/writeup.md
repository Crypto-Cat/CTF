---
Challenge Name: DOM XSS in jQuery selector sink using a hashchange event
Category: XSS
Difficulty: Apprentice
Link: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event
---
[![VIDEO WALKTHROUGH](https://img.youtube.com/vi/JgiX3kyK8ME/0.jpg)](https://youtu.be/JgiX3kyK8ME "DOM XSS in jQuery Selector Sink using a Hashchange Event")

## Background
### What is the DOM?
The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page. Websites can use JavaScript to manipulate the nodes and objects of the DOM, as well as their properties.

DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value (`source`), and passes it into a dangerous function (`sink`).

[List of commonly exploited sources and sinks](https://portswigger.net/web-security/dom-based)
### What is DOM XSS?
DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as `eval()` or `innerHTML`.

The most common source for DOM XSS is the URL, which is typically accessed with the `window.location` object.
### Testing HTML sinks
Place a random alphanumeric string into the source (such as `location.search`), then use devtools (not view-source, which won't account for dynamic changes to HTML) to inspect the HTML and find where your string appears.

For each location where the string appears in the DOM, you need to identify the context and refine input accordingly, e.g. if the string appears within a double-quoted attribute then try to inject double quotes to see if you can break out of the attribute.
### Testing JavaScript execution sinks
With JavaScript execution sinks, your input doesn't necessarily appear anywhere within the DOM, so you can't search for it. Instead you'll need to use the JavaScript debugger to determine whether and how the input is sent to a sink.

If the `source` gets assigned to other variables, you'll need to track the variables and see if they're passed to a `sink`.

When you find a sink being assigned data originating from the source, you can inspect the value in the debugger before it is sent to the sink. Like HTML sinks, you need to refine the input to see if you can deliver a successful XSS attack.
### location.hash
`location.hash`: The `hash` property of the [`Location`](https://developer.mozilla.org/en-US/docs/Web/API/Location) interface returns a string containing a `'#'` followed by the fragment identifier of the URL (ID on the page the URL is trying to target).

The fragment is not [percent-decoded](https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding). If the URL does not have a fragment identifier, this property contains an empty string, `""`.
### DOM XSS in jQuery: hashchange event
A potential sink to look out for is jQuery's `$()` selector function, which can be used to inject malicious objects into the DOM.

The selector is often used conjunction with the `location.hash` source for animations or auto-scrolling to a particular element on the page. This behavior was often implemented using a vulnerable `hashchange` event handler, e.g.
```js
$(window).on('hashchange', function() {
	var element = $(location.hash);
	element[0].scrollIntoView();
});
```
An attacker could exploit the user controllable `hash` to inject an XSS into the `$()` selector sink.

Recent versions of jQuery have patched this specific vulnerability by preventing the injection of HTML into a selector when the input begins with a hash character (`#`).

To exploit, attackers must find a way to trigger a `hashchange` event without user interaction, e.g. with an `iframe`.

In this example, the `src` points to the vulnerable page with an empty hash value. When the `iframe` is loaded, an XSS vector is appended to the hash, triggering the `hashchange` event.
```js
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

## Challenge Description
> This [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event) contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.

>To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

## Solution
Exploring the functionality of the website, we find we are able to view posts and leave comments (`comment`, `name`, `email`, `website`).

Opening DevTools (F12) on the main page and searching for `"hashchange"` in the inspector identifies the following script.
```js
$(window).on('hashchange', function(){
	var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
	if (post) post.get(0).scrollIntoView();
});
```

We can ask ChatGPT to explain the code snippet because.. why not 😁
>This code attaches an event listener to the "hashchange" event on the "window" object, which is triggered when the URL's hash fragment (the part of the URL after the "#" symbol) changes. When the event is triggered, the code creates a variable "post" that selects the first heading (h2) element within a "section" element with the class "blog-list" that contains the text of the current hash fragment (decoded using the "decodeURIComponent" function). If the "post" variable is not null, the code uses the "scrollIntoView" method to scroll the selected heading element into view.

So, if we set a URL like https://LAB-ID.web-security-academy.net/#test and load the page, nothing happens. However, we can still verify the functionality of the code snippet by entering `window.location.hash.slice(1)` in the console, which should return `"test"`.

If we set a URL like https://LAB-ID.web-security-academy.net/#Machine%20Parenting and load the page, the window will scroll the relevant post (`"Machine Parenting"`) as the `if (post)` condition returned true.

Note that the post titles appear to be randomised as my lab instance expired and when I returned, the `"Machine Parenting"` post was missing.

We could also setup a breakpoint at line 84 or 85 (DevTools Debugger) in the index file. This will allow us to analyse the functionality with greater granularity, stepping through each stage.

To exploit the vulnerability, let's place an XSS payload `<img src=x onerror=alert(document.domain)>` in the URL, after the `#`. 

This should trigger an alert since the jquery selector `$()` will first try to select (find) the item on the page and when it fails (the string does not exist in this example), it will add the element.

We need to send a URL to the admin to trigger the `print()` function but there's no indication that the admin will click any link we provide. Therefore, we can use an iFrame to automatically render a URL of our choice.

However, if we try to create an exploit and deliver it to the victim, the XSS does not trigger.
```html
<iframe src="https://LAB-ID.web-security-academy.net/#<img src=x onerror=print()>"></iframe>
```

As discussed earlier, this is because jQuery patched the vulnerability but exploitation is still viable. In the example below, the `src` attribute points to the vulnerable page with an empty hash value. When the `iframe` is loaded, an XSS vector is appended to the hash, causing the `hashchange` event to fire

```html
<iframe src="https://LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

When we `store` the iFrame in the exploit server body and `deliver exploit to victim`, the `print()` function is triggered in the victim/admin's browser and the lab is marked complete 🙂

## Resources
- [OWASP: XSS Types](https://owasp.org/www-community/Types_of_Cross-Site_Scripting)
- [Portswigger DOM Vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [PortSwigger XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PayloadsAllTheThings: XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadBox: XSS](https://github.com/payloadbox/xss-payload-list)
- [HackTricks: XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)