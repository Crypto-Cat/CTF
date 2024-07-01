---
name: Last Hope (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: AI
description: Writeup for Last Hope (AI) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Last Hope

## Description

> The quantum data came back and analyzed. DISASTER! Our best scientists all agree: Unfortunately our species and our whole culture are about to be eliminated. Due to abnormal behavior of the black hole's singularity our planet is about to get swallowed. Project "ONESHOT" is our last hope...

## Solution

Asked ChatGPT to write me a script to run the `quantum_artifact.qasm` file (Quantum Assembly).

{% code overflow="wrap" %}
```python
from qiskit import QuantumCircuit, execute, Aer

# load the quantum circuit from the file
circuit = QuantumCircuit.from_qasm_file('quantum_artifact.qasm')

# execute the circuit on the local simulator
backend = Aer.get_backend('qasm_simulator')
result = execute(circuit, backend).result()

# print the measurement counts
counts = result.get_counts(circuit)
print(counts)
```
{% endcode %}

{% code overflow="wrap" %}
```json
{
    "01001000010101000100001001111011011000010101111101100111011011000011000101101101011100000111001100110011010111110011000001100110010111110110100000110000011100000011001101111101": 1024
}
```
{% endcode %}

[Convert from binary to ASCII](<https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)&input=MDEwMDEwMDAwMTAxMDEwMDAxMDAwMDEwMDExMTEwMTEwMTEwMDAwMTAxMDExMTExMDExMDAxMTEwMTEwMTEwMDAwMTEwMDAxMDExMDExMDEwMTExMDAwMDAxMTEwMDExMDAxMTAwMTEwMTAxMTExMTAwMTEwMDAwMDExMDAxMTAwMTAxMTExMTAxMTAxMDAwMDAxMTAwMDAwMTExMDAwMDAwMTEwMDExMDExMTExMDE>) gets us the flag!

Flag: `HTB{a_gl1mps3_0f_h0p3}`.
