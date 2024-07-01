---
name: Mysterious Learnings (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: AI
description: Writeup for Mysterious Learnings (AI) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Mysterious Learnings

## Description

> One day the archeologist came across a strange metal plate covered in uncommon hieroglyphics. It looked like blueprints for some kind of alien technology. "What kind of magic is this?" He studied the plate more closely and was amazed by the advanced technology and incredible engineering they were using at a time like this. This could only lead him in him wanting to learn more...

## Solution

Challenge looks similar to previous years [Cyber Apocalypse](https://ctftime.org/writeup/27743), even with the same filename `alien.h5` but doesn't come with any training data.

First tried to open the model with [Panoply](https://www.giss.nasa.gov/tools/panoply/download) but didn't find much, can also use python.

{% code overflow="wrap" %}
```python
import h5py
from tensorflow.keras.models import model_from_json

filename = 'alien.h5'
with h5py.File(filename, 'r') as f:
    model_weights_attrs = dict(f['model_weights'].attrs)
    model_architecture = f.attrs['model_config']

model = model_from_json(model_architecture)
model.load_weights(filename)

print("Layers in the model:")
print("=====================")
model.summary()
```
{% endcode %}

{% code overflow="wrap" %}
```bash
SFRCe24wdF9zb
Layers in the model:
=====================
Model: "19oNHJkX3RvX3V"
_________________________________________________________________
 Layer (type)                Output Shape              Param #
=================================================================
 conv2d_3 (Conv2D)           (None, 30, 30, 32)        896

 max_pooling2d_2 (MaxPooling  (None, 15, 15, 32)       0
 2D)

 conv2d_4 (Conv2D)           (None, 13, 13, 64)        18496

 max_pooling2d_3 (MaxPooling  (None, 6, 6, 64)         0
 2D)

 conv2d_5 (Conv2D)           (None, 4, 4, 64)          36928

 uZDNyc3Q0bmR9 (Lambda)      (None, 4, 4, 64)          0

 flatten_1 (Flatten)         (None, 1024)              0

 dense_2 (Dense)             (None, 64)                65600

 dense_3 (Dense)             (None, 10)                650

 lambda_1 (Lambda)           (None, 10)                0

=================================================================
Total params: 122,570
Trainable params: 122,570
Non-trainable params: 0
```
{% endcode %}

Added the base64-y looking strings together: `SFRCe24wdF9zb19oNHJkX3RvX3VuZDNyc3Q0bmR9` and convert with [CyberChef](<https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=U0ZSQ2UyNHdkRjl6YjE5b05ISmtYM1J2WDNWdVpETnljM1EwYm1SOQ>)

Flag: `HTB{n0t_so_h4rd_to_und3rst4nd}`
