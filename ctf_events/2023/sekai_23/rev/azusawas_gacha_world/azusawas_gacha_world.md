---
name: Azusawa’s Gacha World (2023)
event: Sekai CTF 2023
category: Rev
description: Writeup for Azusawa’s Gacha World (Rev) - Sekai CTF (2023) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Azusawa’s Gacha World

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/R8EnhRDDWFg/0.jpg)](https://youtu.be/R8EnhRDDWFg "Reverse Engineering / Game Hacking - 'Azusawa's Gacha World' Walkthrough - Project SEKAI CTF 2023")

## Description

> The website only contains the challenge description, and is not needed to solve the challenge: https://azusawa.world/#/2023/03/02

## Solution

Downloading the [game files](https://storage.googleapis.com/sekaictf-2023/azusawa/dist.zip) we find that the game is Unity (Mono Bleeding Edge), so let's run the game on a Windows VM.

We have 100 credits, which we can use to pull a card - after that we will have zero credits.

I used cheat engine to scan for the value and then increased it to 999999 (check my [cheat engine tutorial series](https://www.youtube.com/playlist?list=PLmqenIp2RQcg0x2mDAyL2MC23DAGcCR9b) if you want to find out how to do this).

Now we can do the 10 card pull, which costs 1000 credits. Each time, we get a different combination of 2 or 3 star cards (but no flag).

Since the game is Unity, we can try to decompile the `Assembly-CSharp.dll` with a tool like DNSpy, recovering the C# code.

Immediately, I noticed some interesting values, e.g. the `Character` class has a `flag` property.

{% code overflow="wrap" %}
```csharp
namespace RequestClasses
{
	// Token: 0x0200000D RID: 13
	[Serializable]
	public class Character
	{
		// Token: 0x04000064 RID: 100
		public string name;

		// Token: 0x04000065 RID: 101
		public string cardName;

		// Token: 0x04000066 RID: 102
		public string rarity;

		// Token: 0x04000067 RID: 103
		public string attribute;

		// Token: 0x04000068 RID: 104
		public string splashArt;

		// Token: 0x04000069 RID: 105
		public string avatar;

		// Token: 0x0400006A RID: 106
		public string flag;
	}
}
```
{% endcode %}

We can check where the character is referenced, and find some interesting functions like `SendGachaRequest` which makes a JSON web request.

I opened Wireshark and pulled some more cards, finding the request.

{% code overflow="wrap" %}
```bash
POST /gacha HTTP/1.1
Host: 172.86.64.89:3000
Accept: */*
Accept-Encoding: deflate, gzip
Content-Type: application/json
User-Agent: SekaiCTF
X-Unity-Version: 2021.3.29f1
Content-Length: 39

{"crystals":100,"pulls":0,"numPulls":1}
```
{% endcode %}

The response includes the card name, rarity etc.

{% code overflow="wrap" %}
```bash
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 26 Aug 2023 08:31:05 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Content-Length: 198

{"characters":[{"name":"......... .........","cardName":"....................................","rarity":"2*","attribute":"Cute","splashArt":"warm-camping-style","avatar":"warm-camping-style-icon"}]}
```
{% endcode %}

Interesting.. I'll save this for later - back to the code.

There's another function called `DisplaySplashArt`, which has a different method to display each card, depending on the rarity.

{% code overflow="wrap" %}
```csharp
public IEnumerator DisplaySplashArt(Character[] characters)
{
	int i;
	Func<bool> <>9__0;
	int j;
	for (i = 0; i < characters.Length; i = j + 1)
	{
		if (this.skipClicked)
		{
			this.skipClicked = false;
			break;
		}
		if (characters[i].rarity == "4*")
		{
			base.StartCoroutine(this.DisplayFourStarCharacter(characters[i]));
		}
		else if (characters[i].rarity == "3*")
		{
			base.StartCoroutine(this.DisplayThreeStarCharacter(characters[i]));
		}
		else
		{
			base.StartCoroutine(this.DisplayTwoStarCharacter(characters[i]));
		}
		yield return new WaitForEndOfFrame();
		Func<bool> func;
		if ((func = <>9__0) == null)
		{
			func = (<>9__0 = () => this.CheckForSkipOrClick(characters, i));
		}
		yield return new WaitUntil(func);
		if (!this.skipClicked)
		{
			AudioController.Instance.PlaySFX("Touch");
		}
		j = i;
	}
	this.DisplayGachaOverview();
	yield break;
}
```
{% endcode %}

Comparing the methods, we see that the `DisplayFourStarCharacter` has an interesting section of code.

{% code overflow="wrap" %}
```csharp
string flag = character.flag;
if (flag != null)
{
	byte[] array = Convert.FromBase64String(flag);
	Texture2D texture2D = new Texture2D(2, 2);
	texture2D.LoadImage(array);
	Rect rect = new Rect(0f, 0f, (float)texture2D.width, (float)texture2D.height);
	Vector2 vector = new Vector2(0.5f, 0.5f);
	Sprite sprite = Sprite.Create(texture2D, rect, vector);
	this.flagImage.sprite = sprite;
}
```
{% endcode %}

Looks like all we need to do is get a 4-star card and we've solved the challenge! First, I patched the code so that all cards would be processed as 4-star (I thought maybe the 2-3 star characters could still have a flag property, that wasn't being extracted/displayed). The patched code looked like:

{% code overflow="wrap" %}
```csharp
public IEnumerator DisplaySplashArt(Character[] characters)
{
    int i;
    int j;
    for (i = 0; i < characters.Length; i = j + 1)
    {
        if (this.skipClicked)
        {
            this.skipClicked = false;
            break;
        }
        if (characters[i].rarity == "4*")
        {
            base.StartCoroutine(this.DisplayFourStarCharacter(characters[i]));
        }
        else if (characters[i].rarity == "3*")
        {
            base.StartCoroutine(this.DisplayFourStarCharacter(characters[i]));
        }
        else
        {
            base.StartCoroutine(this.DisplayFourStarCharacter(characters[i]));
        }
        yield return new WaitForEndOfFrame();
        yield return new WaitUntil(() => this.CheckForSkipOrClick(characters, i));
        if (!this.skipClicked)
        {
            AudioController.Instance.PlaySFX("Touch");
        }
        j = i;
    }
    this.DisplayGachaOverview();
    yield break;
}
```
{% endcode %}

It didn't work though - we saw from the web request that the cards are returned from the server though, this isn't going to be a client-side trick. Maybe we just need to brute-force until we get it? Well, we can check the game rules and find that the odds are as follows.

{% code overflow="wrap" %}
```bash
4 star = 0%
3 star = 8.5%
2 star = 91.5%
```
{% endcode %}

Sounds like we have literally zero chance of getting a 4 star card. I decided to copy the HTTP request we found earlier to burp suite and play around with the values. After a few attempts I came across this one.

{% code overflow="wrap" %}
```bash
POST /gacha HTTP/1.1
Host: 172.86.64.89:3000
Accept: */*
Accept-Encoding: deflate, gzip
Content-Type: application/json
User-Agent: SekaiCTF
X-Unity-Version: 2021.3.29f1
Content-Length: 59

{"crystals":99999999999,"pulls":999999999999,"numPulls":10}
```
{% endcode %}

The response contained a happy-birthday character containing a big base64 blob.

{% code overflow="wrap" %}
```bash
{
  "characters": [
    {
      "name": "こはね 小豆沢",
      "cardName": "Happy Birthday！！2023",
      "rarity": "4*",
      "attribute": "Mysterious",
      "splashArt": "happy-birthday",
      "avatar": "happy-birthday-icon",
      "flag": "redacted due to size"
..........
```
{% endcode %}

We can save the base64 blob to a text file and run `base64 -d file_name > flag` and then check the file type with `file flag`.

It's a PNG image, so we rename to `flag.png` and open it up to find our flag!

Flag: `SEKAI{D0N7_73LL_53G4_1_C0P13D_7H31R_G4M3}`
