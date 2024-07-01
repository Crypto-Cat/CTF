---
name: Perfect Syncronization (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Crypto
description: Writeup for Perfect Syncronization (Crypto) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Perfect Syncronization

## Description

> The final stage of your initialization sequence is mastering cutting-edge technology tools that can be life-changing. One of these tools is quipqiup, an automated tool for frequency analysis and breaking substitution ciphers. This is the ultimate challenge, simulating the use of AES encryption to protect a message. Can you break it?

## Solution

My teammate used a script to map the the output to characters.

{% code overflow="wrap" %}
```python
map = {
    "c53ba24fbbe9e3dbdd6062b3aab7ed1a": "}",
    "fbe86a428051747607a35b44b1a3e9e9": "{",
    "5ae172c9ea46594cea34ad1a4b1c79cd": "e",
    "a94f49727cf771a85831bd03af1caaf5": "_",
    "2fc20e9a20605b988999e836301a2408": "x",
    "60e8373bfb2124aea832f87809fca596": "z",
    "0df9b4e759512f36aaa5c7fd4fb1fba8": "v",
    "293f56083c20759d275db846c8bfb03e": "q",
    "fb78aed37621262392a4125183d1bfc9": "y",
    "66975492b6a53cc9a4503c3a1295b6a7": "n",
    "4a3af0b7397584c4d450c6f7e83076aa": "s",
    "9673dbe632859fa33b8a79d6a3e3fe30": "r",
    "78de2d97da222954cce639cc4b481050": "t",
    "2190a721b2dcb17ff693aa5feecb3b58": "d",
    "dfc8a2232dc2487a5455bda9fa2d45a1": "f",
    "5d7185a6823ab4fc73f3ea33669a7bae": "c",
    "e23c1323abc1fc41331b9cdfc40d5856": "u",
    "d178fac67ec4e9d2724fed6c7b50cd26": "p",
    "3a17ebebf2bad9aa0dd75b37a58fe6ea": "o",
    "457165130940ceac01160ac0ff924d86": "g",
    "f89f2719fb2814d9ab821316dae9862f": "m",
    "8cbd4cfebc9ddf583a108de1a69df088": "a",
    "34ece5ff054feccc5dabe9ae90438f9d": "i",
    "e9b131ab270c54bbf67fb4bd9c8e3177": "b",
    "305d4649e3cb097fb094f8f45abbf0dc": "w",
    "68d763bc4c7a9b0da3828e0b77b08b64": "k",
    "5f122076e17398b7e21d1762a61e2e0a": "j",
    "200ecd2657df0197f202f258b45038d8": "l",
    "c87a7eb9283e59571ad0cb0c89a74379": "h",
    "61331054d82aeec9a20416759766d9d5": " "
}
out = ""
with open("encrypted.txt") as file:
    lines = file.readlines()
    for line in lines:
        out += (map[line.strip()])
print(out)
```
{% endcode %}

{% code overflow="wrap" %}
```bash
python solve.py
fwhzphigc jijmclbl bl rjlhu ai koh fjgk kojk bi jic tbvhi lkwhkgo af nwbkkhi mjitpjth ghwkjbi mhkkhwl jiu gasrbijkbail af mhkkhwl aggpw nbko vjwcbit fwhzphigbhl sawhavhw kohwh bl j gojwjgkhwblkbg ublkwbrpkbai af mhkkhwl kojk bl waptomc koh ljsh faw jmsalk jmm ljsdmhl af kojk mjitpjth bi gwcdkjijmclbl fwhzphigc jijmclbl jmla yiani jl gapikbit mhkkhwl bl koh lkpuc af koh fwhzphigc af mhkkhwl aw twapdl af mhkkhwl bi j gbdohwkhxk koh shkoau bl plhu jl ji jbu ka rwhjybit gmjllbgjm gbdohwl fwhzphigc jijmclbl whzpbwhl aimc j rjlbg piuhwlkjiubit af koh lkjkblkbgl af koh dmjbikhxk mjitpjth jiu lash dwarmhs lamvbit lybmml jiu bf dhwfawshu rc ojiu kamhwjigh faw hxkhilbvh mhkkhw raayyhhdbit upwbit nawmu njw bb rako koh rwbkblo jiu koh jshwbgjil whgwpbkhu gauhrwhjyhwl rc dmjgbit gwallnawu dpqqmhl bi sjeaw ihnldjdhwl jiu wpiibit gaikhlkl faw noa gapmu lamvh kohs koh fjlkhlk lhvhwjm af koh gbdohwl plhu rc koh jxbl danhwl nhwh rwhjyjrmh plbit fwhzphigc jijmclbl faw hxjsdmh lash af koh gailpmjw gbdohwl plhu rc koh ejdjihlh shgojibgjm shkoaul af mhkkhw gapikbit jiu lkjkblkbgjm jijmclbl thihwjmmc okr{j_lbsdmh_lprlkbkpkbai_bl_nhjy} gjwu kcdh sjgobihwc nhwh fbwlk plhu bi nawmu njw bb dallbrmc rc koh pl jwscl lbl kaujc koh ojwu nawy af mhkkhw gapikbit jiu jijmclbl ojl rhhi whdmjghu rc gasdpkhw lafknjwh nobgo gji gjwwc apk lpgo jijmclbl bi lhgaiul nbko sauhwi gasdpkbit danhw gmjllbgjm gbdohwl jwh pimbyhmc ka dwavbuh jic whjm dwakhgkbai faw gaifbuhikbjm ujkj dpqqmh dpqqmh dpqqmh
```
{% endcode %}

I picked up on the challenge and provided to [quipqiup](https://www.quipqiup.com) `statistics mode`.

{% code overflow="wrap" %}
```txt
frequency analysis is based on the fact that in any given stretch of written language certain letters and combinations of letters occur with varying frequencies moreover there is a characteristic distribution of letters that is roughly the same for almost all samples of that language in cryptanalysis frequency analysis also known as counting letters is the study of the frequency of letters or groups of letters in a ciphertext the method is used as an aid to breaking classical ciphers frequency analysis requires only a basic understanding of the statistics of the plaintext language and some problem solving skills and if performed by hand tolerance for extensive letter bookkeeping during world war ii both the british and the americans recruited codebreakers by placing crossword puzzles in major newspapers and running contests for who could solve them the fastest several of the ciphers used by the axis powers were breakable using frequency analysis for example some of the consular ciphers used by the japanese mechanical methods of letter counting and statistical analysis generally htb{a_simple_substitution_is_weak} card type machinery were first used in world war ii possibly by the us armys sis today the hard work of letter counting and analysis has been replaced by computer software which can carry out such analysis in seconds with modern computing power classical ciphers are unlikely to provide any real protection for confidential data puzzle puzzle puzzle
```
{% endcode %}

Flag: `HTB{A_SIMPLE_SUBSTITUTION_IS_WEAK}`
